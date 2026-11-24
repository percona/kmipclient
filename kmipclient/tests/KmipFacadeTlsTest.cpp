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

    // Connects with the default TLS options, trusting only @p ca, through
    // the constructor or create_shared(). Returns the error, or "".
    std::string connect(const TestCert &ca, bool shared = false) {
      try {
        if (shared) {
          (void) Kmip::create_shared(
              "127.0.0.1",
              server.port().c_str(),
              server_cert.cert().c_str(),
              server_cert.key().c_str(),
              ca.cert().c_str(),
              2000
          );
        } else {
          Kmip kmip(
              "127.0.0.1",
              server.port().c_str(),
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

  bool verify_failed(const std::string &error) {
    return error.find("certificate verify failed") != std::string::npos;
  }

}  // namespace

TEST_F(KmipFacadeTlsTest, DefaultRefusesUntrustedCertificate) {
  const std::string error = connect(other_ca);
  EXPECT_TRUE(verify_failed(error)) << error;
}

TEST_F(KmipFacadeTlsTest, CreateSharedDefaultRefusesUntrustedCertificate) {
  const std::string error = connect(other_ca, true);
  EXPECT_TRUE(verify_failed(error)) << error;
}

// Control: the same setup connects when the server can be verified.
TEST_F(KmipFacadeTlsTest, DefaultConnectsToVerifiedServer) {
  EXPECT_EQ(connect(server_cert), "");
  EXPECT_EQ(connect(server_cert, true), "");
}

#else

TEST(KmipFacadeTlsTest, NotOnWindows) {
  GTEST_SKIP() << "uses POSIX sockets for the test server";
}

#endif
