/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// The KMIP server host is a host name or an IP address, without a port; an
// IPv6 address may be in brackets. Anything else is refused before
// connecting, whatever the TLS options and through every entry point.

#include "TlsTestServer.hpp"
#include "kmipclient/Kmip.hpp"
#include "kmipclient/KmipClientPool.hpp"
#include "kmipclient/KmipIOException.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"

#include <chrono>
#include <functional>
#include <gtest/gtest.h>
#include <string>

using kmipclient::KmipIOException;
using kmipclient::NetClientOpenSSL;
using kmipclient::test::Loopback;
using kmipclient::test::TempDir;
using kmipclient::test::TestCert;
using kmipclient::test::TlsTestServer;

namespace {

  // Expects @p connect to throw the KmipIOException for a refused host, with
  // @p error in its message.
  void expect_refused(
      const std::string &what,
      const std::string &error,
      const std::function<void()> &connect
  ) {
    try {
      connect();
      ADD_FAILURE() << what << ": not refused";
    } catch (const KmipIOException &e) {
      EXPECT_EQ(e.code().value(), kmipcore::KMIP_IO_FAILURE) << what;
      EXPECT_NE(std::string(e.what()).find(error), std::string::npos)
          << what << ": " << e.what();
    }
  }

}  // namespace

// No server is needed: the host is checked before anything else, so port 1
// and missing certificate files are never used.
TEST(ServerHostTest, InvalidHostsAreRefused) {
  const std::string empty = "host name must not be empty";
  const std::string nul = "contains a NUL byte";
  const auto invalid = [](const std::string &host) {
    return "host '" + host + "' is not a host name or an IP address";
  };
  const struct {
    std::string host;
    std::string error;
  } hosts[] = {
      {"", empty},
      {std::string("\0kms.example", 12), "host '' " + nul},
      {std::string("127.0.0.1\0kms.example", 21), "host '127.0.0.1' " + nul},
      {":", invalid(":")},
      {":5696", invalid(":5696")},
      {"*", invalid("*")},
      {"*:5696", invalid("*:5696")},
      {"kms.example:5696", invalid("kms.example:5696")},
      {"127.0.0.1:5696", invalid("127.0.0.1:5696")},
      {"a:b:c", invalid("a:b:c")},
      {"[]", invalid("[]")},
      {"[", invalid("[")},
      {"[::1", invalid("[::1")},
      {"[::1]:5696", invalid("[::1]:5696")},
      {"[127.0.0.1]", invalid("[127.0.0.1]")},
      {"[kms.example]", invalid("[kms.example]")},
  };
  const NetClientOpenSSL::TlsVerificationOptions options[] = {
      {true, true}, {false, false}
  };
  for (const auto &[host, error] : hosts) {
    for (const auto &tls : options) {
      expect_refused(
          "host '" + std::string(host.c_str()) + "' (" +
              std::to_string(host.size()) + " bytes), verify " +
              std::to_string(tls.peer_verification),
          error,
          [&] {
            NetClientOpenSSL client(
                host, "1", "no-cert.pem", "no-key.pem", "no-ca.pem", 2000, tls
            );
            client.connect();
          }
      );
    }
  }

  expect_refused("Kmip", empty, [] {
    kmipclient::Kmip kmip(
        "", "1", "no-cert.pem", "no-key.pem", "no-ca.pem", 2000
    );
  });
  kmipclient::KmipClientPool pool(
      kmipclient::KmipClientPool::Config{
          .host = "",
          .port = "1",
          .client_cert = "no-cert.pem",
          .client_key = "no-key.pem",
          .server_ca_cert = "no-ca.pem",
          .timeout_ms = 2000,
      }
  );
  expect_refused("KmipClientPool", empty, [&] { (void) pool.borrow(); });
}

// Control: IP addresses connect with full verification, the IPv6 loopback
// in both spellings.
TEST(ServerHostTest, IpAddressHostsConnect) {
  const struct {
    const char *host;
    Loopback loopback;
    const char *san;
  } hosts[] = {
      {"127.0.0.1", Loopback::IPv4, "IP:127.0.0.1"},
      {"::1", Loopback::IPv6, "IP:::1"},
      {"[::1]", Loopback::IPv6, "IP:::1"},
  };
  for (const auto &h : hosts) {
    SCOPED_TRACE(h.host);
    TempDir dir;
    TestCert cert(dir, "server", h.san);
    TlsTestServer server(cert, {}, std::chrono::seconds(5), h.loopback);
    NetClientOpenSSL client(
        h.host, server.port(), cert.cert(), cert.key(), cert.cert(), 2000
    );
    EXPECT_TRUE(client.connect());
    client.close();
    EXPECT_TRUE(server.wait_for_handshakes(1));
  }
}
