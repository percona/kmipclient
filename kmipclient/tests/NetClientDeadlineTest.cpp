/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// NetClientOpenSSL against a TLS server that answers slowly: timeout_ms must
// bound the whole exchange, whether the response is spread over many reads
// (one TLS record per byte) or over one read (one TLS record sent a byte at a
// time, which OpenSSL assembles from many socket reads).

#include "../src/IOUtils.hpp"
#include "kmipclient/KmipIOException.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"

#include <gtest/gtest.h>

#ifndef _WIN32

  #include "TlsTestServer.hpp"

  #include <chrono>
  #include <cstdint>
  #include <openssl/bio.h>
  #include <string>
  #include <thread>
  #include <vector>

using namespace std::chrono_literals;
using kmipclient::test::TempDir;
using kmipclient::test::TestCert;
using kmipclient::test::TlsTestServer;

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

  enum class Answer {
    at_once,          // the whole response in one TLS record
    record_per_byte,  // one TLS record per byte, 50 ms apart
    byte_per_segment  // one TLS record, written one byte per 50 ms
  };

  // A 100-byte TTLV message: 8-byte header, 92-byte body.
  std::vector<uint8_t> kmip_message() {
    std::vector<uint8_t> msg(100, 0x5A);
    msg[0] = 0x42;
    msg[3] = 0x01;
    msg[4] = msg[5] = msg[6] = 0;
    msg[7] = 92;
    return msg;
  }

  void respond(SSL *ssl, Answer answer) {
    std::vector<uint8_t> request(100);  // read the whole request first
    for (size_t got = 0, n = 0; got < request.size(); got += n) {
      if (SSL_read_ex(ssl, request.data() + got, request.size() - got, &n) !=
          1) {
        return;
      }
    }
    const auto response = kmip_message();
    if (answer == Answer::record_per_byte) {
      for (const uint8_t byte : response) {
        std::this_thread::sleep_for(50ms);
        if (SSL_write(ssl, &byte, 1) != 1) {
          return;  // the client gave up
        }
      }
      return;
    }
    if (answer == Answer::byte_per_segment) {
      // Put the filter between SSL and the socket BIO, which the filter
      // chain now also holds a reference to.
      BIO *sock = SSL_get_wbio(ssl);
      BIO_up_ref(sock);
      SSL_set0_wbio(ssl, BIO_push(BIO_new(trickle_method()), sock));
    }
    SSL_write(ssl, response.data(), static_cast<int>(response.size()));
  }

  struct Outcome {
    std::string error;  // "" when the exchange succeeded
    std::chrono::steady_clock::duration elapsed{};
  };

  Outcome exchange(Answer answer, int timeout_ms) {
    TempDir dir;
    TestCert cert(dir, "server", "IP:127.0.0.1");
    TlsTestServer server(cert, [answer](SSL *ssl) { respond(ssl, answer); });
    kmipclient::NetClientOpenSSL client(
        "127.0.0.1",
        server.port(),
        cert.cert(),
        cert.key(),
        cert.cert(),
        timeout_ms
    );
    kmipclient::IOUtils io(client);
    kmipcore::secure_bytes response;

    // Connect before the clock starts, so a slow handshake cannot pass for
    // a receive timeout.
    client.connect();
    Outcome outcome;
    const auto start = std::chrono::steady_clock::now();
    try {
      io.do_exchange(kmip_message(), response, 1024);
      EXPECT_EQ(response.size(), 100u);
    } catch (const kmipclient::KmipIOException &e) {
      outcome.error = e.what();
    }
    outcome.elapsed = std::chrono::steady_clock::now() - start;
    return outcome;
  }

}  // namespace

TEST(NetClientDeadlineTest, PromptServerSucceeds) {
  EXPECT_EQ(exchange(Answer::at_once, 2000).error, "");
}

TEST(NetClientDeadlineTest, TimeoutBoundsResponseSentOneRecordPerByte) {
  // 100 records take 5 s; each single read is far below 300 ms.
  const Outcome outcome = exchange(Answer::record_per_byte, 300);
  EXPECT_NE(outcome.error.find("receive timed out"), std::string::npos)
      << outcome.error;
  EXPECT_LT(outcome.elapsed, 2s);
}

TEST(NetClientDeadlineTest, TimeoutBoundsOneRecordSentOneBytePerSegment) {
  // One record of about 120 bytes takes about 6 s, all inside one BIO_read.
  const Outcome outcome = exchange(Answer::byte_per_segment, 300);
  EXPECT_NE(outcome.error.find("receive timed out"), std::string::npos)
      << outcome.error;
  EXPECT_LT(outcome.elapsed, 2s);
}

#else

TEST(NetClientDeadlineTest, NotOnWindows) {
  GTEST_SKIP() << "uses POSIX sockets for the test server";
}

#endif
