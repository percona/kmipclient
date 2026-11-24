/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// A host that names no host is refused before connecting, whatever the TLS
// options and through every entry point.

#include "kmipclient/Kmip.hpp"
#include "kmipclient/KmipClientPool.hpp"
#include "kmipclient/KmipIOException.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"

#include <gtest/gtest.h>

#ifndef _WIN32

  #include "TlsTestServer.hpp"

  #include <chrono>
  #include <functional>
  #include <memory>
  #include <string>
  #include <thread>

using kmipclient::NetClientOpenSSL;
using kmipclient::test::TempDir;
using kmipclient::test::TestCert;
using kmipclient::test::TlsTestServer;

namespace {

  // The client trusts the server's CA, but the certificate is issued for
  // another name: only a skipped host name check lets a connection through.
  class EmptyHostTest : public ::testing::Test {
  protected:
    TempDir dir;
    TestCert ca{dir, "ca", "DNS:ca.example"};
    TestCert cert{dir, "server", "DNS:other-host.example", &ca};
    TlsTestServer server{cert};

    std::unique_ptr<NetClientOpenSSL>
        client_for(const std::string &host, bool peer, bool name) {
      return std::make_unique<NetClientOpenSSL>(
          host,
          server.port(),
          cert.cert(),
          cert.key(),
          ca.cert(),
          2000,
          NetClientOpenSSL::TlsVerificationOptions{peer, name}
      );
    }

    void expect_refused(
        const std::string &what, const std::function<void()> &f
    ) {
      try {
        f();
        ADD_FAILURE() << "connected: " << what;
      } catch (const kmipcore::KmipException &e) {
        EXPECT_NE(
            std::string(e.what()).find("host name must not be empty"),
            std::string::npos
        ) << what
          << ": " << e.what();
      }
    }
  };

}  // namespace

TEST_F(EmptyHostTest, HostsThatNameNoHostAreRefused) {
  const std::string hosts[] = {
      "",
      ":",
      ":" + server.port(),
      "[]",
      "*",
      "*:" + server.port(),
      std::string("\0other-host.example", 19),
  };
  for (const bool verify : {true, false}) {
    for (const auto &host : hosts) {
      expect_refused(
          "host '" + host + "', verify " + std::to_string(verify),
          [&] { client_for(host, verify, verify)->connect(); }
      );
    }
  }
  expect_refused("Kmip", [&] {
    kmipclient::Kmip kmip(
        "",
        server.port().c_str(),
        cert.cert().c_str(),
        cert.key().c_str(),
        ca.cert().c_str(),
        2000
    );
  });
  kmipclient::KmipClientPool pool(
      kmipclient::KmipClientPool::Config{
          .host = "",
          .port = server.port(),
          .client_cert = cert.cert(),
          .client_key = cert.key(),
          .server_ca_cert = ca.cert(),
          .timeout_ms = 2000,
      }
  );
  expect_refused("KmipClientPool", [&] { (void) pool.borrow(); });

  // Give a connection that was started anyway time to reach the server.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  EXPECT_EQ(server.handshakes(), 0);
}

TEST_F(EmptyHostTest, ControlLoopbackAddressConnects) {
  // The same server is reachable by address once the name check is off.
  const auto client = client_for("127.0.0.1", true, false);
  EXPECT_TRUE(client->connect());
  EXPECT_TRUE(server.wait_for_handshakes(1));
}

#else

TEST(EmptyHostTest, NotOnWindows) {
  GTEST_SKIP() << "uses POSIX sockets for the test server";
}

#endif
