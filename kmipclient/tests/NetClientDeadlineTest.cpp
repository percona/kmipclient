/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// NetClientOpenSSL against a TLS server that answers slowly: timeout_ms must
// bound the whole exchange, whether the response is spread over many reads
// (one TLS record per byte) or over one read (one TLS record sent a byte at a
// time, which OpenSSL assembles from many socket reads), and however the
// waits in between end.

#include "../src/BioDeadline.hpp"
#include "../src/IOUtils.hpp"
#include "TlsTestServer.hpp"
#include "kmipclient/KmipIOException.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <span>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
  #include <csignal>
  #include <pthread.h>
#endif

using namespace std::chrono_literals;
using kmipclient::KmipIOException;
using kmipclient::NetClientOpenSSL;
using kmipclient::test::Socket;
using kmipclient::test::tcp_connect;
using kmipclient::test::TempDir;
using kmipclient::test::TestCert;
using kmipclient::test::TlsTestServer;
using Clock = kmipclient::NetClient::Clock;

namespace {

  // Filter BIO that writes one byte per call, 50 ms apart.
  int trickle_write(BIO *bio, const char *data, size_t len, size_t *written) {
    std::this_thread::sleep_for(50ms);
    return BIO_write_ex(BIO_next(bio), data, len > 0 ? 1 : 0, written);
  }

  long trickle_ctrl(BIO *bio, int cmd, long num, void *ptr) {
    return BIO_ctrl(BIO_next(bio), cmd, num, ptr);
  }

  BIO_METHOD *trickle_method() {
    static BIO_METHOD *method = [] {
      BIO_METHOD *m =
          BIO_meth_new(BIO_get_new_index() | BIO_TYPE_FILTER, "trickle");
      BIO_meth_set_write_ex(m, trickle_write);
      BIO_meth_set_ctrl(m, trickle_ctrl);
      BIO_meth_set_create(m, [](BIO *b) {
        BIO_set_init(b, 1);
        return 1;
      });
      return m;
    }();
    return method;
  }

  // A 100-byte TTLV message: 8-byte header, 92-byte body.
  std::vector<uint8_t> kmip_message() {
    std::vector<uint8_t> msg(100, 0x5A);
    msg[0] = 0x42;
    msg[3] = 0x01;
    msg[4] = msg[5] = msg[6] = 0;
    msg[7] = 92;
    return msg;
  }

  // Opened when the test is over, so that a handler that waits on it
  // returns at once.
  class Gate {
  public:
    void open() {
      std::call_once(once_, [this] { promise_.set_value(); });
    }
    // Waits up to timeout; true when the gate opened.
    [[nodiscard]] bool wait(std::chrono::milliseconds timeout) const {
      return opened_.wait_for(timeout) == std::future_status::ready;
    }

  private:
    std::promise<void> promise_;
    std::shared_future<void> opened_ = promise_.get_future().share();
    std::once_flag once_;
  };

  // A server with a self-signed certificate, and a client for it.
  struct Peer {
    using Handler = std::function<void(SSL *, const Gate &)>;

    Peer(Handler handler, int timeout_ms)
      : cert(dir, "server", "IP:127.0.0.1"),
        server(
            cert,
            [this, handler = std::move(handler)](SSL *ssl) {
              handler(ssl, gate);
            }
        ),
        client(
            "127.0.0.1",
            server.port(),
            cert.cert(),
            cert.key(),
            cert.cert(),
            timeout_ms
        ) {}
    ~Peer() { gate.open(); }  // before the members are destroyed
    Peer(const Peer &) = delete;
    Peer &operator=(const Peer &) = delete;

    Gate gate;
    TempDir dir;
    TestCert cert;
    TlsTestServer server;
    NetClientOpenSSL client;
  };

  // Reads the whole 100-byte request; false when the client went away.
  bool read_request(SSL *ssl) {
    std::vector<uint8_t> request(100);
    for (size_t got = 0, n = 0; got < request.size(); got += n) {
      if (SSL_read_ex(ssl, request.data() + got, request.size() - got, &n) !=
          1) {
        return false;
      }
    }
    return true;
  }

  // Blocks until the client closes the connection.
  void wait_for_client(SSL *ssl) {
    uint8_t byte = 0;
    while (SSL_read(ssl, &byte, 1) > 0) {}
  }

  // Writes data as one TLS record after delay; false when the test is over
  // or the client went away.
  bool write_after(
      SSL *ssl,
      const Gate &gate,
      std::chrono::milliseconds delay,
      std::span<const uint8_t> data
  ) {
    return !gate.wait(delay) &&
           SSL_write(ssl, data.data(), static_cast<int>(data.size())) ==
               static_cast<int>(data.size());
  }

  // Writes one TLS record per byte, pause apart.
  void write_record_per_byte(
      SSL *ssl,
      const Gate &gate,
      std::chrono::milliseconds pause,
      std::span<const uint8_t> data
  ) {
    for (size_t i = 0; i < data.size(); ++i) {
      if (!write_after(ssl, gate, pause, data.subspan(i, 1))) {
        return;
      }
    }
  }

  // Writes one TLS record, one byte per 50 ms. The filter goes between SSL
  // and the socket BIO, which the filter chain then also holds a reference
  // to.
  void write_byte_per_segment(SSL *ssl, std::span<const uint8_t> data) {
    BIO *sock = SSL_get_wbio(ssl);
    BIO_up_ref(sock);
    SSL_set0_wbio(ssl, BIO_push(BIO_new(trickle_method()), sock));
    SSL_write(ssl, data.data(), static_cast<int>(data.size()));
  }

  struct Outcome {
    std::string error;  // "" when the exchange succeeded
    Clock::duration elapsed{};
  };

  // Connects, then times one exchange of request.
  Outcome timed_exchange(
      NetClientOpenSSL &client, const std::vector<uint8_t> &request
  ) {
    kmipclient::IOUtils io(client);
    kmipcore::secure_bytes response;

    // Connect before the clock starts, so a slow handshake cannot pass for
    // a timeout of the exchange.
    EXPECT_TRUE(client.connect());
    Outcome outcome;
    const auto start = Clock::now();
    try {
      io.do_exchange(request, response, 1024);
      EXPECT_EQ(response.size(), 100u);
    } catch (const KmipIOException &e) {
      outcome.error = e.what();
    }
    outcome.elapsed = Clock::now() - start;
    return outcome;
  }

  testing::AssertionResult
      contains(const std::string &text, const std::string &part) {
    if (text.find(part) != std::string::npos) {
      return testing::AssertionSuccess();
    }
    return testing::AssertionFailure()
        << "\"" << text << "\" does not contain \"" << part << "\"";
  }

  constexpr const char *kReceiveDeadline =
      "KMIP receive timed out: exchange deadline passed";

}  // namespace

TEST(NetClientDeadlineTest, PromptServerSucceeds) {
  Peer peer(
      [](SSL *ssl, const Gate &gate) {
        if (read_request(ssl)) {
          write_after(ssl, gate, 0ms, kmip_message());
        }
      },
      2000
  );
  EXPECT_EQ(timed_exchange(peer.client, kmip_message()).error, "");
}

TEST(NetClientDeadlineTest, TimeoutBoundsResponseSentOneRecordPerByte) {
  // 100 records take 5 s; each single read is far below 300 ms.
  Peer peer(
      [](SSL *ssl, const Gate &gate) {
        if (read_request(ssl)) {
          write_record_per_byte(ssl, gate, 50ms, kmip_message());
        }
      },
      300
  );
  const Outcome outcome = timed_exchange(peer.client, kmip_message());
  EXPECT_TRUE(contains(outcome.error, kReceiveDeadline));
  EXPECT_LT(outcome.elapsed, 2s);
}

TEST(NetClientDeadlineTest, TimeoutBoundsOneRecordSentOneBytePerSegment) {
  // One record of about 120 bytes takes about 6 s, all inside one BIO_read.
  Peer peer(
      [](SSL *ssl, const Gate &) {
        if (read_request(ssl)) {
          write_byte_per_segment(ssl, kmip_message());
        }
      },
      300
  );
  const Outcome outcome = timed_exchange(peer.client, kmip_message());
  EXPECT_TRUE(contains(outcome.error, kReceiveDeadline));
  EXPECT_LT(outcome.elapsed, 2s);
}

// The header comes after 400 ms, within the 600 ms timeout, and the body
// later still. A recv() that waited timeout_ms from its own start would end
// at about 1000 ms.
TEST(NetClientDeadlineTest, DeadlineSpansSeparateReads) {
  Peer peer(
      [](SSL *ssl, const Gate &gate) {
        const auto response = kmip_message();
        if (read_request(ssl) &&
            write_after(ssl, gate, 400ms, std::span(response).first(8))) {
          write_after(ssl, gate, 3s, std::span(response).subspan(8));
        }
      },
      600
  );
  const Outcome outcome = timed_exchange(peer.client, kmip_message());
  EXPECT_TRUE(contains(outcome.error, kReceiveDeadline));
  EXPECT_LT(outcome.elapsed, 850ms);
}

TEST(NetClientDeadlineTest, ResponseWithinTheTimeoutSucceeds) {
  Peer peer(
      [](SSL *ssl, const Gate &gate) {
        if (read_request(ssl)) {
          write_after(ssl, gate, 300ms, kmip_message());
        }
      },
      600
  );
  EXPECT_EQ(timed_exchange(peer.client, kmip_message()).error, "");
}

// The server reads nothing, so a request far larger than the socket buffers
// cannot be sent.
TEST(NetClientDeadlineTest, TimeoutBoundsTheSend) {
  Peer peer([](SSL *, const Gate &gate) { (void) gate.wait(10s); }, 300);
  const std::vector<uint8_t> request(64 << 20, 0x42);
  const Outcome outcome = timed_exchange(peer.client, request);
  EXPECT_TRUE(
      contains(outcome.error, "KMIP send timed out: exchange deadline passed")
  );
  EXPECT_LT(outcome.elapsed, 2s);
}

// Without an exchange deadline, a single call waits timeout_ms.
TEST(NetClientDeadlineTest, WithoutDeadlineEachCallHasTimeoutMs) {
  Peer peer([](SSL *ssl, const Gate &) { wait_for_client(ssl); }, 300);
  ASSERT_TRUE(peer.client.connect());
  std::array<uint8_t, 4> buf{};
  const auto start = Clock::now();
  try {
    peer.client.recv(buf);
    ADD_FAILURE() << "recv() did not time out";
  } catch (const KmipIOException &e) {
    EXPECT_TRUE(contains(e.what(), "KMIP receive timed out after 300ms"));
  }
  const auto elapsed = Clock::now() - start;
  EXPECT_GE(elapsed, 300ms);
  EXPECT_LT(elapsed, 2s);
}

// The timeout fires when the deadline has passed, not up to a millisecond
// before it.
TEST(NetClientDeadlineTest, TimeoutIsNotReportedEarly) {
  Peer peer([](SSL *ssl, const Gate &) { wait_for_client(ssl); }, 2000);
  ASSERT_TRUE(peer.client.connect());
  std::array<uint8_t, 4> buf{};
  for (const auto offset : {40600us, 20300us, 10900us}) {
    const auto deadline = Clock::now() + offset;
    peer.client.set_io_deadline(deadline);
    EXPECT_THROW(peer.client.recv(buf), KmipIOException);
    EXPECT_GE(Clock::now(), deadline);
  }
}

// timeout_ms <= 0: a blocking socket and no timeout, so a slow response is
// received.
TEST(NetClientDeadlineTest, NoTimeoutWhenTimeoutIsNotPositive) {
  for (const int timeout_ms : {0, -1}) {
    SCOPED_TRACE(timeout_ms);
    Peer prompt(
        [](SSL *ssl, const Gate &gate) {
          if (read_request(ssl)) {
            write_after(ssl, gate, 0ms, kmip_message());
          }
        },
        timeout_ms
    );
    EXPECT_EQ(timed_exchange(prompt.client, kmip_message()).error, "");

    Peer slow(
        [](SSL *ssl, const Gate &gate) {
          if (read_request(ssl)) {
            write_record_per_byte(ssl, gate, 5ms, kmip_message());
          }
        },
        timeout_ms
    );
    EXPECT_EQ(timed_exchange(slow.client, kmip_message()).error, "");
  }
}

// TLS control records the client must process but that carry no data: one
// SSL_read() must not keep processing them past the deadline.
TEST(NetClientDeadlineTest, FloodOfControlRecordsIsBounded) {
  const struct {
    const char *name;
    int (*queue)(SSL *);
  } floods[] = {
      {"NewSessionTicket",
       [](SSL *ssl) { return SSL_new_session_ticket(ssl); }},
      {"KeyUpdate", [](SSL *ssl) {
         return SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED);
       }},
  };
  for (const auto &flood : floods) {
    SCOPED_TRACE(flood.name);
    // Sends the records as fast as it can for 3 s, or until the client
    // goes away.
    Peer peer(
        [&flood](SSL *ssl, const Gate &) {
          if (!read_request(ssl)) {
            return;
          }
          const auto until = Clock::now() + 3s;
          while (Clock::now() < until && flood.queue(ssl) == 1 &&
                 SSL_do_handshake(ssl) == 1) {}
        },
        300
    );
    const Outcome outcome = timed_exchange(peer.client, kmip_message());
    EXPECT_TRUE(contains(outcome.error, kReceiveDeadline));
    EXPECT_LT(outcome.elapsed, 1500ms);
  }
}

// A deadline more than INT_MAX ms away must not be cut to its remainder
// modulo 2^32 ms when it is passed to poll().
TEST(NetClientDeadlineTest, WaitIsNotCutShortForAFarDeadline) {
  TempDir dir;
  TestCert cert(dir, "server", "IP:127.0.0.1");
  // The server gives up on the handshake after 400 ms and closes the
  // connection, which ends the wait.
  TlsTestServer server(cert, {}, 400ms);
  const Socket socket = tcp_connect(server.port());
  ASSERT_TRUE(socket.valid());
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(
      BIO_new_socket(static_cast<int>(socket.get()), BIO_NOCLOSE), BIO_free
  );
  ASSERT_TRUE(bio);
  BIO_set_retry_read(bio.get());

  const auto start = Clock::now();
  kmipclient::detail::wait_for_bio_retry(
      bio.get(),
      start + std::chrono::milliseconds((1LL << 32) + 200),
      "receive",
      1000,
      true
  );
  EXPECT_GE(Clock::now() - start, 350ms);
}

// A BIO_read() that asks to be retried for neither reading nor writing is
// returned to the caller, not waited on.
TEST(NetClientDeadlineTest, RetryForNeitherReadNorWriteIsReturned) {
  static BIO_METHOD *method = [] {
    BIO_METHOD *m = BIO_meth_new(
        BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "retry special"
    );
    BIO_meth_set_read(m, [](BIO *b, char *, int) {
      BIO_clear_retry_flags(b);
      BIO_set_retry_special(b);
      return -1;
    });
    BIO_meth_set_create(m, [](BIO *b) {
      BIO_set_init(b, 1);
      return 1;
    });
    return m;
  }();
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(method), BIO_free);
  ASSERT_TRUE(bio);
  char byte = 0;
  int ret = 1;
  EXPECT_NO_THROW(
      ret = kmipclient::detail::io_with_deadline(
          bio.get(), std::nullopt, 5000, "receive", [&] {
            return BIO_read(bio.get(), &byte, 1);
          }
      )
  );
  EXPECT_LE(ret, 0);
}

#ifndef _WIN32

// A signal every 20 ms interrupts each wait; the deadline must still hold.
TEST(NetClientDeadlineTest, SignalsDoNotPostponeTheDeadline) {
  struct sigaction action{};
  struct sigaction previous{};
  action.sa_handler = [](int) {
  };
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;  // no SA_RESTART
  ASSERT_EQ(sigaction(SIGUSR1, &action, &previous), 0);

  Peer peer(
      [](SSL *ssl, const Gate &) {
        if (read_request(ssl)) {
          wait_for_client(ssl);
        }
      },
      300
  );
  const pthread_t client_thread = pthread_self();
  std::atomic<bool> done{false};
  std::thread signaller([&] {
    const auto until = Clock::now() + 3s;
    while (!done && Clock::now() < until) {
      pthread_kill(client_thread, SIGUSR1);
      std::this_thread::sleep_for(20ms);
    }
  });
  const Outcome outcome = timed_exchange(peer.client, kmip_message());
  done = true;
  signaller.join();
  sigaction(SIGUSR1, &previous, nullptr);

  EXPECT_TRUE(contains(outcome.error, kReceiveDeadline));
  EXPECT_LT(outcome.elapsed, 1500ms);
}

#endif
