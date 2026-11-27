/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// Checks the test helpers themselves: TempDir, TestCert and TlsTestServer.

#include "TlsTestServer.hpp"

#include "kmipclient/NetClientOpenSSL.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <thread>

#ifndef _WIN32
  #include <csignal>
#endif

using kmipclient::test::Loopback;
using kmipclient::test::Socket;
using kmipclient::test::tcp_connect;
using kmipclient::test::TempDir;
using kmipclient::test::TestCert;
using kmipclient::test::TlsTestServer;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::steady_clock;

namespace {

  std::unique_ptr<X509, decltype(&X509_free)>
      read_cert(const std::string &path) {
    std::unique_ptr<X509, decltype(&X509_free)> x(nullptr, X509_free);
    if (BIO *b = BIO_new_file(path.c_str(), "r"); b != nullptr) {
      x.reset(PEM_read_bio_X509(b, nullptr, nullptr, nullptr));
      BIO_free(b);
    }
    return x;
  }

  kmipclient::NetClientOpenSSL client_for(
      const TlsTestServer &server, const TestCert &cert, const TestCert &ca
  ) {
    return {
        "127.0.0.1", server.port(), cert.cert(), cert.key(), ca.cert(), 2000
    };
  }

}  // namespace

TEST(TlsTestServerTest, TempDirIsPrivateAndRemoved) {
  std::filesystem::path path;
  {
    TempDir dir;
    TempDir other;
    path = dir.path();
    EXPECT_NE(path, other.path());
    EXPECT_TRUE(std::filesystem::is_directory(path));
#ifndef _WIN32
    EXPECT_EQ(
        std::filesystem::status(path).permissions(),
        std::filesystem::perms::owner_all
    );
#endif
    std::ofstream(path / "file") << "x";
  }
  EXPECT_FALSE(std::filesystem::exists(path));
}

// Each certificate as the tests use it: a CA-signed leaf, and a self-signed
// certificate that is both the server certificate and its own CA.
TEST(TlsTestServerTest, CertificatesPassStrictVerification) {
  TempDir dir;
  TestCert ca(dir, "ca", "DNS:unused.example");
  TestCert leaf(dir, "leaf", "IP:127.0.0.1", &ca);
  TestCert self(dir, "self", "IP:127.0.0.1");

  const struct {
    const TestCert &cert;
    const TestCert &trusted;
  } cases[] = {{leaf, ca}, {self, self}};
  for (const auto &c : cases) {
    SCOPED_TRACE(c.cert.cert());
    auto cert = read_cert(c.cert.cert());
    auto trusted = read_cert(c.trusted.cert());
    ASSERT_TRUE(cert && trusted);
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(
        X509_STORE_new(), X509_STORE_free
    );
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx(
        X509_STORE_CTX_new(), X509_STORE_CTX_free
    );
    ASSERT_EQ(X509_STORE_add_cert(store.get(), trusted.get()), 1);
    ASSERT_EQ(
        X509_STORE_CTX_init(ctx.get(), store.get(), cert.get(), nullptr), 1
    );
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx.get());
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);
    X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_SERVER);
    X509_VERIFY_PARAM_set1_ip_asc(param, "127.0.0.1");
    EXPECT_EQ(X509_verify_cert(ctx.get()), 1)
        << X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get()));

#ifndef _WIN32
    EXPECT_EQ(
        std::filesystem::status(c.cert.key()).permissions(),
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write
    );
#endif
  }

  auto ca_x509 = read_cert(ca.cert());
  auto leaf_x509 = read_cert(leaf.cert());
  ASSERT_TRUE(ca_x509 && leaf_x509);
  EXPECT_NE(
      ASN1_INTEGER_cmp(
          X509_get0_serialNumber(ca_x509.get()),
          X509_get0_serialNumber(leaf_x509.get())
      ),
      0
  );
}

TEST(TlsTestServerTest, VerifiedClientExchangesData) {
  TempDir dir;
  TestCert ca(dir, "ca", "DNS:unused.example");
  TestCert cert(dir, "server", "IP:127.0.0.1", &ca);
  TlsTestServer server(cert, [](SSL *ssl) {
    std::array<std::uint8_t, 4> buf{};
    if (SSL_read(ssl, buf.data(), 4) == 4) {
      SSL_write(ssl, buf.data(), 4);
    }
  });

  auto client = client_for(server, cert, ca);
  ASSERT_TRUE(client.connect());
  const std::array<std::uint8_t, 4> request{1, 2, 3, 4};
  std::array<std::uint8_t, 4> response{};
  ASSERT_EQ(client.send(request), 4);
  ASSERT_EQ(client.recv(response), 4);
  EXPECT_EQ(response, request);

  client.close();
  EXPECT_TRUE(server.wait_for_completed(1));
  // No second connection comes, so the wait ends on its timeout.
  EXPECT_FALSE(server.wait_for_completed(2, milliseconds(50)));
  EXPECT_EQ(server.handshakes(), 1);
  EXPECT_EQ(server.error(), "");
}

// With Loopback::IPv6 the server listens on ::1.
TEST(TlsTestServerTest, Ipv6ServerAcceptsAConnectionToIpv6Loopback) {
  TempDir dir;
  TestCert cert(dir, "server", "IP:::1");
  TlsTestServer server(cert, {}, seconds(5), Loopback::IPv6);

  kmipclient::NetClientOpenSSL client(
      "[::1]", server.port(), cert.cert(), cert.key(), cert.cert(), 2000
  );
  client.set_tls_verification({true, false});  // the chain only
  EXPECT_TRUE(client.connect());
  client.close();
  EXPECT_TRUE(server.wait_for_completed(1));
  EXPECT_EQ(server.handshakes(), 1);
  EXPECT_EQ(server.error(), "");
}

// After the handler returns, the client reads a TLS close_notify, not a
// bare end of stream.
TEST(TlsTestServerTest, ServerSendsCloseNotify) {
  TempDir dir;
  TestCert cert(dir, "server", "IP:127.0.0.1");
  TlsTestServer server(cert);

  const Socket socket = tcp_connect(server.port());
  ASSERT_TRUE(socket.valid());
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
      SSL_CTX_new(TLS_client_method()), SSL_CTX_free
  );
  ASSERT_TRUE(ctx);
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), SSL_free);
  ASSERT_TRUE(ssl);
  ASSERT_EQ(SSL_set_fd(ssl.get(), static_cast<int>(socket.get())), 1);
  ASSERT_EQ(SSL_connect(ssl.get()), 1);
  std::uint8_t byte = 0;
  const int n = SSL_read(ssl.get(), &byte, 1);
  EXPECT_EQ(n, 0);
  EXPECT_EQ(SSL_get_error(ssl.get(), n), SSL_ERROR_ZERO_RETURN);
}

// The first error is kept, whatever the handler throws; the server goes on
// serving after a handler throws.
TEST(TlsTestServerTest, FirstHandlerErrorIsKept) {
  const struct {
    const char *name;
    std::function<void()> first_throw;
    const char *expected;
  } cases[] = {
      {"what()", [] { throw std::runtime_error("boom"); }, "boom"},
      {"empty what()",
       [] { throw std::runtime_error(""); },
       "exception with an empty message"},
      {"not a std::exception", [] { throw 42; }, "unknown exception"},
  };

  TempDir dir;
  TestCert cert(dir, "server", "IP:127.0.0.1");
  for (const auto &c : cases) {
    SCOPED_TRACE(c.name);
    std::atomic<int> calls{0};
    TlsTestServer server(cert, [&](SSL *) {
      if (calls++ == 0) {
        c.first_throw();
      }
      throw std::runtime_error("second");
    });
    for (int i = 1; i <= 2; ++i) {
      auto client = client_for(server, cert, cert);
      ASSERT_TRUE(client.connect());
      ASSERT_TRUE(server.wait_for_completed(i));
    }
    EXPECT_EQ(server.handshakes(), 2);
    EXPECT_EQ(server.error(), c.expected);
  }
}

// read_timeout ends a handler whose client sends nothing, without stop(),
// while the client is still connected.
TEST(TlsTestServerTest, ReadTimeoutEndsAStalledClient) {
  TempDir dir;
  TestCert cert(dir, "server", "IP:127.0.0.1");
  std::atomic<long long> blocked_ms{-1};
  TlsTestServer server(
      cert,
      [&blocked_ms](SSL *ssl) {
        const auto start = steady_clock::now();
        std::uint8_t byte = 0;
        (void) SSL_read(ssl, &byte, 1);  // the client never sends
        blocked_ms = std::chrono::duration_cast<milliseconds>(
                         steady_clock::now() - start
        )
                         .count();
      },
      milliseconds(300)
  );

  auto client = client_for(server, cert, cert);
  ASSERT_TRUE(client.connect());
  ASSERT_TRUE(server.wait_for_completed(1, seconds(3)));
  EXPECT_GE(blocked_ms.load(), 250);
  EXPECT_LT(blocked_ms.load(), 3000);
}

// stop() ends a blocked handler at once (the read timeout is far longer),
// and closes the listening socket.
TEST(TlsTestServerTest, StopEndsAWaitingHandler) {
  TempDir dir;
  TestCert cert(dir, "server", "IP:127.0.0.1");
  TlsTestServer server(
      cert,
      [](SSL *ssl) {
        std::uint8_t byte = 0;
        (void) SSL_read(ssl, &byte, 1);  // the client never sends
      },
      seconds(60)
  );

  auto client = client_for(server, cert, cert);
  ASSERT_TRUE(client.connect());
  ASSERT_TRUE(server.wait_for_handshakes(1));
  const auto start = steady_clock::now();
  server.stop();
  EXPECT_LT(steady_clock::now() - start, seconds(2));
  EXPECT_EQ(server.completed(), 1);
  EXPECT_FALSE(tcp_connect(server.port()).valid());
}

#ifndef _WIN32

// While a server exists, a client's writes to a connection the server has
// closed do not end the process with SIGPIPE; the disposition from before
// comes back with the last server.
TEST(TlsTestServerTest, SigpipeIsIgnoredWhileAServerExists) {
  // Start from the default disposition, whatever the process inherited, and
  // put the inherited one back at the end.
  struct Restore {
    struct sigaction original{};
    ~Restore() { sigaction(SIGPIPE, &original, nullptr); }
  } restore;
  struct sigaction default_action{};
  default_action.sa_handler = SIG_DFL;
  sigemptyset(&default_action.sa_mask);
  ASSERT_EQ(sigaction(SIGPIPE, &default_action, &restore.original), 0);
  {
    TempDir dir;
    TestCert cert(dir, "server", "IP:127.0.0.1");
    TlsTestServer server(cert);  // closes each connection after the handshake
    auto client = client_for(server, cert, cert);
    ASSERT_TRUE(client.connect());
    ASSERT_TRUE(server.wait_for_completed(1));
    // The first write after the server closed may still be accepted; a
    // later one fails with EPIPE.
    const std::array<std::uint8_t, 1> byte{1};
    bool failed = false;
    for (int i = 0; i < 50 && !failed; ++i) {
      failed = client.send(byte) <= 0;
      if (!failed) {
        std::this_thread::sleep_for(milliseconds(20));
      }
    }
    EXPECT_TRUE(failed) << "no write hit the closed connection";
    struct sigaction during{};
    ASSERT_EQ(sigaction(SIGPIPE, nullptr, &during), 0);
    EXPECT_EQ(during.sa_handler, SIG_IGN);
  }
  struct sigaction after{};
  ASSERT_EQ(sigaction(SIGPIPE, nullptr, &after), 0);
  EXPECT_EQ(after.sa_handler, SIG_DFL);
}

#endif
