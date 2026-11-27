/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// The Kmip facade verifies the server certificate unless the caller opts out.

#include "kmipclient/Kmip.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <gtest/gtest.h>

#ifndef _WIN32

  #include "TlsTestServer.hpp"

  #include <openssl/x509.h>
  #include <string>

using kmipclient::Kmip;
using kmipclient::test::TempDir;
using kmipclient::test::TestCert;
using kmipclient::test::TlsTestServer;

namespace {

  class KmipFacadeTlsTest : public ::testing::Test {
  protected:
    TempDir dir;
    TestCert server_cert{dir, "server", "IP:127.0.0.1"};
    TestCert other_ca{dir, "other-ca", "IP:127.0.0.1"};  // not the server's
    TlsTestServer server{server_cert};
    // Trusted when passed as the CA, but issued for another host name.
    TestCert dns_only{dir, "dns-only", "DNS:other.example"};
    TlsTestServer dns_only_server{dns_only};

    // Connects to @p to with the default TLS options, trusting only @p ca,
    // through the constructor or create_shared(). Returns the error, or "".
    std::string
        connect(const TlsTestServer &to, const TestCert &ca, bool shared) {
      try {
        if (shared) {
          (void) Kmip::create_shared(
              "127.0.0.1",
              to.port().c_str(),
              server_cert.cert().c_str(),
              server_cert.key().c_str(),
              ca.cert().c_str(),
              2000
          );
        } else {
          Kmip kmip(
              "127.0.0.1",
              to.port().c_str(),
              server_cert.cert().c_str(),
              server_cert.key().c_str(),
              ca.cert().c_str(),
              2000
          );
        }
        return "";
      } catch (const kmipcore::KmipException &e) {
        return e.what();
      }
    }
  };

  // True when the handshake was refused for the verify result @p reason.
  bool verify_failed(const std::string &error, long reason) {
    return error.find("certificate verify failed") != std::string::npos &&
           error.find(
               std::string("verification error: ") +
               X509_verify_cert_error_string(reason)
           ) != std::string::npos;
  }

  const char *entry_point(bool shared) {
    return shared ? "create_shared()" : "constructor";
  }

}  // namespace

TEST_F(KmipFacadeTlsTest, DefaultRefusesUntrustedCertificate) {
  for (const bool shared : {false, true}) {
    SCOPED_TRACE(entry_point(shared));
    const std::string error = connect(server, other_ca, shared);
    EXPECT_TRUE(verify_failed(error, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT))
        << error;
  }
}

TEST_F(KmipFacadeTlsTest, DefaultRefusesCertificateForAnotherHost) {
  for (const bool shared : {false, true}) {
    SCOPED_TRACE(entry_point(shared));
    const std::string error = connect(dns_only_server, dns_only, shared);
    EXPECT_TRUE(verify_failed(error, X509_V_ERR_IP_ADDRESS_MISMATCH)) << error;
  }
}

// Control: the same setup connects when the server can be verified.
TEST_F(KmipFacadeTlsTest, DefaultConnectsToVerifiedServer) {
  for (const bool shared : {false, true}) {
    SCOPED_TRACE(entry_point(shared));
    EXPECT_EQ(connect(server, server_cert, shared), "");
  }
}

#else

TEST(KmipFacadeTlsTest, NotOnWindows) {
  GTEST_SKIP() << "uses POSIX sockets for the test server";
}

#endif
