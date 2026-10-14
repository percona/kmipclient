/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

/**
 * @file KmipClientIntegrationTest_2_0.cpp
 * @brief Integration tests exercising KMIP 2.0-specific wire encoding.
 *
 * All tests in this suite connect using protocol version 2.0.  The primary
 * difference from the 1.4 suite is that requests carry the new
 * Attributes container tag (0x420125) instead of legacy TemplateAttribute /
 * Attribute wrappers.  Tests that are not meaningful for a 2.0 server
 * (e.g. single-shot Register+Activate via the ID-placeholder mechanism) are
 * enabled here and NOT marked DISABLED.
 *
 * @note These tests require a KMIP 2.0-capable server.  Set the same
 * environment variables as for the 1.4 suite:
 *   KMIP_ADDR, KMIP_PORT, KMIP_CLIENT_CA, KMIP_CLIENT_KEY, KMIP_SERVER_CA
 * Optional:
 *   KMIP_TIMEOUT_MS (default 5000)
 *   KMIP_RUN_2_0_TESTS=1 (required to enable this suite)
 */

#include "TestEnvUtils.hpp"
#include "kmipclient/Kmip.hpp"
#include "kmipclient/KmipClient.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/kmip_protocol.hpp"
#include "kmiputil/KeyReader.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <gtest/gtest.h>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#define TEST_GROUP "tests_2_0"

using namespace kmipclient;

static std::string TESTING_NAME_PREFIX = "tests_2_0_";

// ---------------------------------------------------------------------------
// Environment-variable configuration (shared singleton)
// ---------------------------------------------------------------------------
class KmipTestConfig20 {
public:
  static KmipTestConfig20 &getInstance() {
    static KmipTestConfig20 instance;
    return instance;
  }

  [[nodiscard]] bool isConfigured() const {
    return !kmip_addr.empty() && !kmip_port.empty() &&
           !kmip_client_ca.empty() && !kmip_client_key.empty() &&
           !kmip_server_ca.empty();
  }

  [[nodiscard]] bool is2_0_enabled() const { return run_2_0_tests; }

  std::string kmip_addr;
  std::string kmip_port;
  std::string kmip_client_ca;
  std::string kmip_client_key;
  std::string kmip_server_ca;
  int timeout_ms;
  bool run_2_0_tests = false;

private:
  KmipTestConfig20() {
    const char *addr = std::getenv("KMIP_ADDR");
    const char *port = std::getenv("KMIP_PORT");
    const char *client_ca = std::getenv("KMIP_CLIENT_CA");
    const char *client_key = std::getenv("KMIP_CLIENT_KEY");
    const char *server_ca = std::getenv("KMIP_SERVER_CA");
    const char *timeout = std::getenv("KMIP_TIMEOUT_MS");

    if (addr) {
      kmip_addr = addr;
    }
    if (port) {
      kmip_port = port;
    }
    if (client_ca) {
      kmip_client_ca = client_ca;
    }
    if (client_key) {
      kmip_client_key = client_key;
    }
    if (server_ca) {
      kmip_server_ca = server_ca;
    }
    run_2_0_tests = kmipclient::test::is_env_flag_enabled("KMIP_RUN_2_0_TESTS");

    timeout_ms = 5000;
    if (timeout) {
      errno = 0;
      char *end = nullptr;
      const long parsed = std::strtol(timeout, &end, 10);
      if (errno == 0 && end != timeout && *end == '\0' && parsed >= 0 &&
          parsed <= INT_MAX) {
        timeout_ms = static_cast<int>(parsed);
      }
    }

    if (!isConfigured()) {
      std::cerr << "WARNING: KMIP environment variables not set. "
                   "KMIP 2.0 tests will be skipped.\n"
                << "Required variables:\n"
                << "  KMIP_ADDR\n"
                << "  KMIP_PORT\n"
                << "  KMIP_CLIENT_CA\n"
                << "  KMIP_CLIENT_KEY\n"
                << "  KMIP_SERVER_CA\n";
    }

    if (!run_2_0_tests) {
      std::cerr << "INFO: KMIP_RUN_2_0_TESTS is not set. "
                   "KMIP 2.0 tests will not run.\n"
                << "Set KMIP_RUN_2_0_TESTS=1 to enable the KMIP 2.0 suite.\n";
    }
  }
};

namespace {

  struct VersionProbeResult {
    bool can_probe = false;
    bool supports_kmip_2_0 = false;
    std::vector<kmipcore::ProtocolVersion> advertised_versions;
    std::string details;
  };

  std::string
      format_versions(const std::vector<kmipcore::ProtocolVersion> &versions) {
    if (versions.empty()) {
      return "<none>";
    }

    std::string out;
    for (size_t i = 0; i < versions.size(); ++i) {
      if (i > 0) {
        out += ", ";
      }
      out += std::to_string(versions[i].getMajor());
      out += ".";
      out += std::to_string(versions[i].getMinor());
    }
    return out;
  }

  const VersionProbeResult &probe_server_versions_once() {
    static const VersionProbeResult result = []() {
      auto &config = KmipTestConfig20::getInstance();
      if (!config.isConfigured()) {
        return VersionProbeResult{
            false, false, {}, "KMIP environment variables are not configured"
        };
      }

      try {
        // Probe with KMIP 1.4 for negotiation safety, then inspect Discover
        // Versions.
        Kmip kmip(
            config.kmip_addr.c_str(),
            config.kmip_port.c_str(),
            config.kmip_client_ca.c_str(),
            config.kmip_client_key.c_str(),
            config.kmip_server_ca.c_str(),
            config.timeout_ms,
            kmipcore::KMIP_VERSION_1_4,
            nullptr,
            NetClient::TlsVerificationOptions{
                .peer_verification = true,
                .hostname_verification = false,
            }
        );
        const auto versions = kmip.client().op_discover_versions();
        const bool supports_2_0 = std::any_of(
            versions.begin(),
            versions.end(),
            [](const kmipcore::ProtocolVersion &v) {
              return v.getMajor() == 2 && v.getMinor() == 0;
            }
        );
        return VersionProbeResult{
            true,
            supports_2_0,
            versions,
            supports_2_0 ? "server advertises KMIP 2.0"
                         : "server does not advertise KMIP 2.0"
        };
      } catch (const std::exception &e) {
        return VersionProbeResult{
            false,
            false,
            {},
            std::string("Discover Versions probe failed: ") + e.what()
        };
      }
    }();
    return result;
  }

}  // namespace

// ---------------------------------------------------------------------------
// Base fixture
// ---------------------------------------------------------------------------
class KmipClientIntegrationTest20 : public ::testing::Test {
protected:
  inline static std::vector<std::string> passed_tests_{};
  inline static std::vector<std::string> failed_tests_{};
  inline static std::vector<std::string> skipped_tests_{};
  inline static bool suite_enabled_ = true;

  static void SetUpTestSuite() {
    auto &config = KmipTestConfig20::getInstance();
    suite_enabled_ = config.is2_0_enabled();
    if (!suite_enabled_) {
      std::cout << "\n[KMIP 2.0 Suite] KMIP_RUN_2_0_TESTS is not set; suite is "
                   "disabled."
                << std::endl;
      return;
    }

    const auto &probe = probe_server_versions_once();
    std::cout << "\n[KMIP 2.0 Suite] Discover Versions pre-check" << std::endl;
    if (probe.can_probe) {
      std::cout << "[KMIP 2.0 Suite] Advertised server versions: "
                << format_versions(probe.advertised_versions) << std::endl;
      std::cout << "[KMIP 2.0 Suite] " << probe.details << std::endl;
    } else {
      std::cout << "[KMIP 2.0 Suite] Version probe unavailable: "
                << probe.details << std::endl;
    }
  }

  static void TearDownTestSuite() {
    if (!suite_enabled_) {
      std::cout << "\n[KMIP 2.0 Suite] Capability summary: not evaluated "
                   "(suite disabled by KMIP_RUN_2_0_TESTS)."
                << std::endl;
      return;
    }

    std::cout << "\n[KMIP 2.0 Suite] Capability summary (from test outcomes)"
              << std::endl;
    std::cout << "[KMIP 2.0 Suite] Supported (passed): " << passed_tests_.size()
              << std::endl;
    for (const auto &name : passed_tests_) {
      std::cout << "  + " << name << std::endl;
    }

    std::cout << "[KMIP 2.0 Suite] Not supported or failing (failed): "
              << failed_tests_.size() << std::endl;
    for (const auto &name : failed_tests_) {
      std::cout << "  - " << name << std::endl;
    }

    std::cout << "[KMIP 2.0 Suite] Not evaluated (skipped): "
              << skipped_tests_.size() << std::endl;
    for (const auto &name : skipped_tests_) {
      std::cout << "  ~ " << name << std::endl;
    }
  }

  std::vector<std::string> created_ids;

  void SetUp() override {
    auto &config = KmipTestConfig20::getInstance();

    if (!config.is2_0_enabled()) {
      GTEST_SKIP() << "KMIP 2.0: suite disabled because KMIP_RUN_2_0_TESTS is "
                      "not set";
    }

    if (!config.isConfigured()) {
      GTEST_SKIP() << "KMIP 2.0: environment variables not configured";
    }

    const auto &version_probe = probe_server_versions_once();
    if (version_probe.can_probe && !version_probe.supports_kmip_2_0) {
      GTEST_SKIP() << "KMIP 2.0: skipping suite because "
                   << version_probe.details;
    }

    // Probe connectivity with a zero-result op_all – fast and side-effect free.
    try {
      auto kmip = createKmipClient();
      (void) kmip->client().op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0);
    } catch (const std::exception &e) {
      GTEST_SKIP() << "KMIP 2.0: server connectivity check failed: "
                   << e.what();
    }
  }

  void TearDown() override {
    if (!suite_enabled_) {
      return;
    }

    const auto *test_info =
        ::testing::UnitTest::GetInstance()->current_test_info();

    if (test_info != nullptr) {
      const auto *result = test_info->result();
      if (result != nullptr && result->Skipped()) {
        skipped_tests_.emplace_back(test_info->name());
      } else if (HasFailure()) {
        failed_tests_.emplace_back(test_info->name());
      } else {
        passed_tests_.emplace_back(test_info->name());
      }
    }

    if (HasFailure()) {
      std::cout << test_info->name() << ": FAIL" << std::endl;
    } else {
      std::cout << test_info->name() << ": OK" << std::endl;
    }

    // Best-effort cleanup of objects created during the test.
    auto &config = KmipTestConfig20::getInstance();
    if (config.isConfigured() && !created_ids.empty()) {
      try {
        Kmip kmip(
            config.kmip_addr.c_str(),
            config.kmip_port.c_str(),
            config.kmip_client_ca.c_str(),
            config.kmip_client_key.c_str(),
            config.kmip_server_ca.c_str(),
            config.timeout_ms,
            kmipcore::KMIP_VERSION_2_0,
            nullptr,
            NetClient::TlsVerificationOptions{
                .peer_verification = true,
                .hostname_verification = false,
            }
        );
        for (const auto &id : created_ids) {
          try {
            (void) kmip.client().op_revoke(
                id,
                revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE,
                "Test cleanup",
                0
            );
            (void) kmip.client().op_destroy(id);
          } catch (kmipcore::KmipException &e) {
            std::cerr << "Cleanup: failed to destroy " << id << ": " << e.what()
                      << std::endl;
          }
        }
      } catch (...) {
        // Silently ignore cleanup errors.
      }
    }
  }

  static std::unique_ptr<Kmip> createKmipClient() {
    auto &config = KmipTestConfig20::getInstance();
    try {
      return std::make_unique<Kmip>(
          config.kmip_addr.c_str(),
          config.kmip_port.c_str(),
          config.kmip_client_ca.c_str(),
          config.kmip_client_key.c_str(),
          config.kmip_server_ca.c_str(),
          config.timeout_ms,
          kmipcore::KMIP_VERSION_2_0,
          nullptr,
          NetClient::TlsVerificationOptions{
              .peer_verification = true,
              .hostname_verification = false,
          }
      );
    } catch (const std::exception &e) {
      throw std::runtime_error(
          std::string("Failed to initialise KMIP 2.0 client: ") + e.what()
      );
    }
  }

  void trackForCleanup(const std::string &id) { created_ids.push_back(id); }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Test: Verify the configured protocol version is 2.0
TEST_F(KmipClientIntegrationTest20, ProtocolVersionIs20) {
  auto kmip = createKmipClient();
  const auto &ver = kmip->client().protocol_version();
  EXPECT_EQ(ver.getMajor(), 2);
  EXPECT_EQ(ver.getMinor(), 0);
  std::cout << "Protocol version: " << ver.getMajor() << "." << ver.getMinor()
            << std::endl;
}

// Test: Create AES key via KMIP 2.0 Attributes container encoding
TEST_F(KmipClientIntegrationTest20, CreateSymmetricAESKey) {
  auto kmip = createKmipClient();
  try {
    const std::string id128 = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "CreateAES128", TEST_GROUP, aes_key_size::AES_128
    );
    const std::string id256 = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "CreateAES256", TEST_GROUP, aes_key_size::AES_256
    );
    trackForCleanup(id128);
    trackForCleanup(id256);

    auto key128 = kmip->client().op_get_key(id128);
    auto key256 = kmip->client().op_get_key(id256);

    EXPECT_EQ(key128->value().size(), 16u);  // 128 bits
    EXPECT_EQ(key256->value().size(), 32u);  // 256 bits

    std::cout << "AES-128 id: " << id128 << ", AES-256 id: " << id256
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "CreateSymmetricAESKey (2.0) failed: " << e.what();
  }
}

// Test: Create and Get key – round-trip
TEST_F(KmipClientIntegrationTest20, CreateAndGetKey) {
  auto kmip = createKmipClient();
  try {
    const auto id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "CreateAndGetKey", TEST_GROUP
    );
    trackForCleanup(id);

    auto key = kmip->client().op_get_key(id);
    ASSERT_NE(key, nullptr);
    EXPECT_EQ(key->value().size(), 32u);  // default AES-256
    std::cout << "Retrieved key size: " << key->value().size() << " bytes"
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "CreateAndGetKey (2.0) failed: " << e.what();
  }
}

// Test: Create, Activate and confirm state == ACTIVE
TEST_F(KmipClientIntegrationTest20, CreateActivateAndGetKey) {
  auto kmip = createKmipClient();
  try {
    const auto id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "CreateActivateGet", TEST_GROUP
    );
    trackForCleanup(id);

    const auto activated_id = kmip->client().op_activate(id);
    EXPECT_EQ(activated_id, id);

    auto key = kmip->client().op_get_key(id);
    ASSERT_NE(key, nullptr);
    ASSERT_FALSE(key->value().empty());

    auto attrs = kmip->client().op_get_attributes(id, {KMIP_ATTR_NAME_STATE});
    EXPECT_EQ(attrs.object_state(), state::KMIP_STATE_ACTIVE)
        << "Key should be ACTIVE after activation";

    std::cout << "Activated key id: " << id << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "CreateActivateAndGetKey (2.0) failed: " << e.what();
  }
}

// Test: Register symmetric key using KMIP 2.0 Attributes encoding
TEST_F(KmipClientIntegrationTest20, RegisterSymmetricKey) {
  auto kmip = createKmipClient();
  const std::vector<unsigned char> key_value = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  };
  try {
    const auto id = kmip->client().op_register_key(
        TESTING_NAME_PREFIX + "RegisterSymmetricKey",
        TEST_GROUP,
        kmiputil::KeyReader::aes_from_value(key_value)
    );
    EXPECT_FALSE(id.empty());
    trackForCleanup(id);
    std::cout << "Registered symmetric key id: " << id << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "RegisterSymmetricKey (2.0) failed: " << e.what();
  }
}

// Test: Register symmetric key, then activate it explicitly via KMIP 2.0
TEST_F(KmipClientIntegrationTest20, RegisterThenActivateSymmetricKey) {
  auto kmip = createKmipClient();
  const std::vector<unsigned char> key_value = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  };

  std::string id;
  try {
    id = kmip->client().op_register_key(
        TESTING_NAME_PREFIX + "RegisterThenActivateKey",
        TEST_GROUP,
        kmiputil::KeyReader::aes_from_value(key_value)
    );
    ASSERT_FALSE(id.empty());
    trackForCleanup(id);
    const auto activated_id = kmip->client().op_activate(id);
    EXPECT_EQ(activated_id, id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "RegisterThenActivateSymmetricKey (2.0) failed: " << e.what();
  }

  try {
    auto key = kmip->client().op_get_key(id);
    ASSERT_NE(key, nullptr);
    ASSERT_FALSE(key->value().empty());

    auto attrs = kmip->client().op_get_attributes(id, {KMIP_ATTR_NAME_STATE});
    EXPECT_EQ(attrs.object_state(), state::KMIP_STATE_ACTIVE)
        << "Key should be ACTIVE immediately after explicit activate";

    std::cout << "RegisterThenActivate key id: " << id << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Get after RegisterThenActivateKey (2.0) failed: " << e.what();
  }
}

// Test: Register secret data via KMIP 2.0
TEST_F(KmipClientIntegrationTest20, RegisterAndGetSecret) {
  auto kmip = createKmipClient();
  const std::vector<unsigned char> secret_data = {'s', 'e', 'c', 'r', 'e', 't'};
  kmipcore::Attributes secret_attrs;
  secret_attrs.set_state(state::KMIP_STATE_PRE_ACTIVE);
  const Secret secret(
      secret_data, secret_data_type::KMIP_SECDATA_PASSWORD, secret_attrs
  );

  std::string id;
  try {
    id = kmip->client().op_register_secret(
        TESTING_NAME_PREFIX + "RegisterSecret", TEST_GROUP, secret
    );
    EXPECT_FALSE(id.empty());
    trackForCleanup(id);
    std::cout << "Registered secret id: " << id << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "op_register_secret (2.0) failed: " << e.what();
  }

  try {
    const auto activated_id = kmip->client().op_activate(id);
    EXPECT_EQ(activated_id, id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "op_activate for secret (2.0) failed: " << e.what();
  }

  try {
    auto retrieved = kmip->client().op_get_secret(id, true);
    EXPECT_EQ(retrieved.value(), secret_data);
    EXPECT_EQ(retrieved.get_state(), state::KMIP_STATE_ACTIVE);
    std::cout << "Retrieved secret size: " << retrieved.value().size()
              << " bytes, state ACTIVE" << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "op_get_secret (2.0) failed: " << e.what();
  }
}

// Test: Register secret, then activate it explicitly via KMIP 2.0
TEST_F(KmipClientIntegrationTest20, RegisterThenActivateSecret) {
  auto kmip = createKmipClient();
  const std::vector<unsigned char> secret_data = {'p', 'a', 's', 's', 'w', 'd'};
  kmipcore::Attributes secret_attrs;
  secret_attrs.set_state(state::KMIP_STATE_PRE_ACTIVE);
  const Secret secret(
      secret_data, secret_data_type::KMIP_SECDATA_PASSWORD, secret_attrs
  );

  std::string id;
  try {
    id = kmip->client().op_register_secret(
        TESTING_NAME_PREFIX + "RegisterThenActivateSecret", TEST_GROUP, secret
    );
    ASSERT_FALSE(id.empty());
    trackForCleanup(id);
    const auto activated_id = kmip->client().op_activate(id);
    EXPECT_EQ(activated_id, id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "RegisterThenActivateSecret (2.0) failed: " << e.what();
  }

  try {
    auto retrieved = kmip->client().op_get_secret(id, true);
    EXPECT_EQ(retrieved.value(), secret_data);
    EXPECT_EQ(retrieved.get_state(), state::KMIP_STATE_ACTIVE)
        << "Secret should be ACTIVE immediately after explicit activate";
    std::cout << "RegisterThenActivate secret id: " << id << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Get after RegisterThenActivateSecret (2.0) failed: " << e.what();
  }
}

// Test: Locate keys by name
TEST_F(KmipClientIntegrationTest20, LocateKeysByName) {
  auto kmip = createKmipClient();
  const std::string name = TESTING_NAME_PREFIX + "LocateByName";
  try {
    const auto id = kmip->client().op_create_aes_key(name, TEST_GROUP);
    trackForCleanup(id);

    auto found = kmip->client().op_locate_by_name(
        name, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY
    );
    EXPECT_FALSE(found.empty());
    const auto it = std::find(found.begin(), found.end(), id);
    EXPECT_NE(it, found.end()) << "Newly created key not found by name";
    std::cout << "Locate by name returned " << found.size() << " result(s)"
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "LocateKeysByName (2.0) failed: " << e.what();
  }
}

// Test: Locate keys by group
TEST_F(KmipClientIntegrationTest20, LocateKeysByGroup) {
  auto kmip = createKmipClient();
  const std::string group =
      "test_2_0_locate_group_" + std::to_string(std::time(nullptr));
  std::vector<std::string> expected_ids;

  try {
    for (int i = 0; i < 3; ++i) {
      const auto id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocateByGroup_" + std::to_string(i), group
      );
      expected_ids.push_back(id);
      trackForCleanup(id);
    }

    auto found = kmip->client().op_locate_by_group(
        group, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY
    );

    for (const auto &expected_id : expected_ids) {
      const auto it = std::find(found.begin(), found.end(), expected_id);
      EXPECT_NE(it, found.end())
          << "Key " << expected_id << " not found in group " << group;
    }
    std::cout << "Locate by group found " << found.size() << " key(s)"
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "LocateKeysByGroup (2.0) failed: " << e.what();
  }
}

TEST_F(
    KmipClientIntegrationTest20, LocatePageByGroupSinglePageReturnsExpectedIds
) {
  auto kmip = createKmipClient();
  const std::string group =
      "test_2_0_locate_page_group_" + std::to_string(std::time(nullptr));
  std::vector<std::string> created;

  try {
    for (int i = 0; i < 3; ++i) {
      const auto id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocatePageByGroup_" + std::to_string(i), group
      );
      created.push_back(id);
      trackForCleanup(id);
    }

    std::optional<std::size_t> located_items;
    auto page = kmip->client().op_locate_page_by_group(
        group, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 2, &located_items
    );
    EXPECT_EQ(page.size(), 2u);
    for (const auto &id : page) {
      EXPECT_NE(std::find(created.begin(), created.end(), id), created.end());
    }
  } catch (kmipcore::KmipException &e) {
    FAIL() << "LocatePageByGroupSinglePageReturnsExpectedIds (2.0) failed: "
           << e.what();
  }
}

TEST_F(
    KmipClientIntegrationTest20,
    LocatePageByGroupIteratesDeterministicallyWithOffset
) {
  auto kmip = createKmipClient();
  const std::string group =
      "test_2_0_locate_page_iter_" + std::to_string(std::time(nullptr));
  std::vector<std::string> created;

  try {
    for (int i = 0; i < 5; ++i) {
      const auto id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocatePageIter_" + std::to_string(i), group
      );
      created.push_back(id);
      trackForCleanup(id);
    }

    std::optional<std::size_t> first_located_items;
    auto first_page = kmip->client().op_locate_page_by_group(
        group,
        object_type::KMIP_OBJTYPE_SYMMETRIC_KEY,
        0,
        2,
        &first_located_items
    );
    auto first_page_repeat = kmip->client().op_locate_page_by_group(
        group, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 2, nullptr
    );
    ASSERT_FALSE(first_page.empty());
    EXPECT_EQ(first_page, first_page_repeat);

    std::vector<std::string> paged_ids = first_page;
    std::vector<std::string> previous_page = first_page;
    std::size_t offset = first_page.size();
    bool offset_honored = false;
    for (std::size_t i = 0; i < 8; ++i) {
      auto page = kmip->client().op_locate_page_by_group(
          group, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, offset, 2, nullptr
      );
      if (page.empty()) {
        break;
      }
      if (page != previous_page) {
        offset_honored = true;
      }
      paged_ids.insert(paged_ids.end(), page.begin(), page.end());
      if (page == previous_page) {
        break;
      }
      offset += page.size();
      previous_page = page;
      if (page.size() < 2) {
        break;
      }
    }

    auto one_shot = kmip->client().op_locate_by_group(
        group, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, created.size()
    );
    if (offset_honored) {
      EXPECT_EQ(paged_ids, one_shot);
    } else {
      EXPECT_GE(one_shot.size(), first_page.size());
      EXPECT_EQ(
          std::vector<std::string>(
              one_shot.begin(),
              one_shot.begin() + static_cast<std::ptrdiff_t>(first_page.size())
          ),
          first_page
      );
    }
    for (const auto &id : paged_ids) {
      EXPECT_NE(
          std::find(one_shot.begin(), one_shot.end(), id), one_shot.end()
      );
    }
    for (const auto &id : created) {
      EXPECT_NE(
          std::find(one_shot.begin(), one_shot.end(), id), one_shot.end()
      );
    }
  } catch (kmipcore::KmipException &e) {
    FAIL()
        << "LocatePageByGroupIteratesDeterministicallyWithOffset (2.0) failed: "
        << e.what();
  }
}

TEST_F(
    KmipClientIntegrationTest20,
    LocatePageByGroupReportsLocatedItemsWhenServerProvidesIt
) {
  auto kmip = createKmipClient();
  const std::string group =
      "test_2_0_locate_page_total_" + std::to_string(std::time(nullptr));
  const auto &protocol_version = kmip->client().protocol_version();

  try {
    for (int i = 0; i < 2; ++i) {
      const auto id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocatePageTotal_" + std::to_string(i), group
      );
      trackForCleanup(id);
    }

    std::optional<std::size_t> located_items;
    auto page = kmip->client().op_locate_page_by_group(
        group, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 10, &located_items
    );

    if (!located_items.has_value()) {
      std::cout << "KMIP " << protocol_version.getMajor() << "."
                << protocol_version.getMinor()
                << ": server omitted optional LocatePayload/LocatedItems; "
                   "skipping total-count assertion as expected by spec"
                << std::endl;
      GTEST_SKIP() << "KMIP " << protocol_version.getMajor() << "."
                   << protocol_version.getMinor()
                   << ": server omitted optional LocatePayload/LocatedItems; "
                      "skip is expected because KMIP Locate responses MAY omit "
                      "Located Items";
    }
    EXPECT_GE(*located_items, page.size());
  } catch (kmipcore::KmipException &e) {
    FAIL() << "LocatePageByGroupReportsLocatedItemsWhenServerProvidesIt "
           << "(KMIP " << protocol_version.getMajor() << "."
           << protocol_version.getMinor() << ") failed: " << e.what();
  }
}

TEST_F(
    KmipClientIntegrationTest20, LocatePageByGroupWithZeroPageSizeReturnsEmpty
) {
  auto kmip = createKmipClient();
  try {
    std::optional<std::size_t> located_items = 1;
    auto page = kmip->client().op_locate_page_by_group(
        "", object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 0, &located_items
    );
    EXPECT_TRUE(page.empty());
    EXPECT_FALSE(located_items.has_value());
  } catch (kmipcore::KmipException &e) {
    FAIL() << "LocatePageByGroupWithZeroPageSizeReturnsEmpty (2.0) failed: "
           << e.what();
  }
}

// Test: op_locate_by_group respects max_ids upper bound
TEST_F(KmipClientIntegrationTest20, LocateKeysByGroupHonorsMaxIds) {
  auto kmip = createKmipClient();
  const std::string group =
      "test_2_0_locate_limit_" + std::to_string(std::time(nullptr));
  std::vector<std::string> created;

  try {
    for (int i = 0; i < 3; ++i) {
      const auto id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocateLimit_" + std::to_string(i), group
      );
      created.push_back(id);
      trackForCleanup(id);
    }

    const size_t max_ids = 2;
    auto found = kmip->client().op_locate_by_group(
        group, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, max_ids
    );

    EXPECT_LE(found.size(), max_ids);
    EXPECT_EQ(found.size(), max_ids);
    for (const auto &id : found) {
      EXPECT_NE(std::find(created.begin(), created.end(), id), created.end())
          << "Located id " << id << " was not created by this test";
    }
  } catch (kmipcore::KmipException &e) {
    FAIL() << "LocateKeysByGroupHonorsMaxIds (2.0) failed: " << e.what();
  }
}

// Test: Get attributes – Name and Object Group
TEST_F(KmipClientIntegrationTest20, CreateAndGetAttributes) {
  auto kmip = createKmipClient();
  const std::string name = TESTING_NAME_PREFIX + "GetAttributes";
  try {
    const auto id = kmip->client().op_create_aes_key(name, TEST_GROUP);
    trackForCleanup(id);

    auto attrs = kmip->client().op_get_attributes(id, {KMIP_ATTR_NAME_NAME});
    attrs.merge(kmip->client().op_get_attributes(id, {KMIP_ATTR_NAME_GROUP}));

    EXPECT_EQ(attrs.get(KMIP_ATTR_NAME_NAME), name);
    EXPECT_EQ(attrs.get(KMIP_ATTR_NAME_GROUP), TEST_GROUP);
    std::cout << "Attributes verified for id: " << id << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "CreateAndGetAttributes (2.0) failed: " << e.what();
  }
}

// Test: Register key and verify NAME and CryptographicUsageMask attributes
TEST_F(KmipClientIntegrationTest20, RegisterKeyAndGetAttributes) {
  auto kmip = createKmipClient();
  const std::string name = TESTING_NAME_PREFIX + "RegisterKeyAttrs";
  const std::vector<unsigned char> key_value = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  };
  try {
    auto key = kmiputil::KeyReader::aes_from_value(key_value);
    const auto expected_mask = static_cast<cryptographic_usage_mask>(
        kmipcore::KMIP_CRYPTOMASK_ENCRYPT | kmipcore::KMIP_CRYPTOMASK_DECRYPT |
        kmipcore::KMIP_CRYPTOMASK_MAC_GENERATE
    );
    key.attributes().set_usage_mask(expected_mask);

    const auto id = kmip->client().op_register_key(name, TEST_GROUP, key);
    EXPECT_FALSE(id.empty());
    trackForCleanup(id);

    auto attrs = kmip->client().op_get_attributes(
        id, {KMIP_ATTR_NAME_NAME, KMIP_ATTR_NAME_CRYPTO_USAGE_MASK}
    );
    EXPECT_EQ(attrs.get(KMIP_ATTR_NAME_NAME), name);
    EXPECT_EQ(attrs.usage_mask(), expected_mask);
    std::cout << "Registered key attributes verified for id: " << id
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "RegisterKeyAndGetAttributes (2.0) failed: " << e.what();
  }
}

// Test: Revoke changes state to DEACTIVATED
TEST_F(KmipClientIntegrationTest20, RevokeChangesState) {
  auto kmip = createKmipClient();
  try {
    const auto id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "RevokeState", TEST_GROUP
    );
    trackForCleanup(id);

    (void) kmip->client().op_activate(id);
    const auto revoke_id = kmip->client().op_revoke(
        id,
        revocation_reason_type::KMIP_REVOKE_UNSPECIFIED,
        "Integration test revoke",
        0
    );
    EXPECT_FALSE(revoke_id.empty());

    auto attrs = kmip->client().op_get_attributes(id, {KMIP_ATTR_NAME_STATE});
    EXPECT_EQ(attrs.object_state(), state::KMIP_STATE_DEACTIVATED)
        << "Expected DEACTIVATED after revoke";
    std::cout << "State is DEACTIVATED after revoke for id: " << id
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "RevokeChangesState (2.0) failed: " << e.what();
  }
}

// Test: Full lifecycle – Create / Activate / Get / Revoke / Destroy
TEST_F(KmipClientIntegrationTest20, FullKeyLifecycle) {
  auto kmip = createKmipClient();
  try {
    // 1. Create
    const auto id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "FullLifecycle", TEST_GROUP
    );
    std::cout << "1. Created key: " << id << std::endl;

    // 2. Activate
    const auto activated_id = kmip->client().op_activate(id);
    ASSERT_FALSE(activated_id.empty());
    std::cout << "2. Activated key" << std::endl;

    // 3. Get
    auto key = kmip->client().op_get_key(id);
    ASSERT_NE(key, nullptr);
    ASSERT_FALSE(key->value().empty());
    std::cout << "3. Retrieved key (" << key->value().size() << " bytes)"
              << std::endl;

    // 4. Revoke
    const auto revoked_id = kmip->client().op_revoke(
        id,
        revocation_reason_type::KMIP_REVOKE_UNSPECIFIED,
        "Full lifecycle test",
        0
    );
    ASSERT_FALSE(revoked_id.empty());
    std::cout << "4. Revoked key" << std::endl;

    // 5. Destroy
    const auto destroyed_id = kmip->client().op_destroy(id);
    EXPECT_EQ(destroyed_id, id);
    std::cout << "5. Destroyed key" << std::endl;

    // No cleanup tracking – already destroyed.
  } catch (kmipcore::KmipException &e) {
    FAIL() << "FullKeyLifecycle (2.0) failed: " << e.what();
  }
}

// Test: Destroy removes the key (retrieval should fail or return empty)
TEST_F(KmipClientIntegrationTest20, DestroyKeyRemovesKey) {
  auto kmip = createKmipClient();
  std::string id;
  try {
    id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "DestroyRemoves", TEST_GROUP
    );
    ASSERT_FALSE(id.empty());
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Create failed: " << e.what();
  }

  try {
    const auto destroyed = kmip->client().op_destroy(id);
    EXPECT_EQ(destroyed, id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Destroy failed: " << e.what();
  }

  try {
    auto key = kmip->client().op_get_key(id);
    EXPECT_TRUE(key->value().empty())
        << "Destroyed key should not be retrievable";
  } catch (kmipcore::KmipException &) {
    // Server may return an error for a destroyed object – acceptable.
    SUCCEED();
  }
  std::cout << "Destroyed key is not retrievable" << std::endl;
}

// Test: Get non-existent key returns a meaningful server error
TEST_F(KmipClientIntegrationTest20, GetNonExistentKey) {
  auto kmip = createKmipClient();
  const std::string fake_id = "non-existent-key-2-0-12345";
  try {
    auto key = kmip->client().op_get_key(fake_id);
    (void) key;
    FAIL() << "Expected exception for non-existent key";
  } catch (const kmipcore::KmipException &e) {
    const std::string msg = e.what();
    EXPECT_NE(msg.find("Operation: Get"), std::string::npos)
        << "Expected Get operation failure, got: " << msg;
    EXPECT_NE(msg.find("Result reason:"), std::string::npos)
        << "Expected Result Reason in error, got: " << msg;
    std::cout << "Non-existent key error details verified" << std::endl;
  }
}

// Test: Get non-existent secret returns a meaningful server error
TEST_F(KmipClientIntegrationTest20, GetNonExistentSecret) {
  auto kmip = createKmipClient();
  const std::string fake_id = "non-existent-secret-2-0-12345";
  try {
    auto secret = kmip->client().op_get_secret(fake_id);
    (void) secret;
    FAIL() << "Expected exception for non-existent secret";
  } catch (const kmipcore::KmipException &e) {
    const std::string msg = e.what();
    EXPECT_NE(msg.find("Operation: Get"), std::string::npos)
        << "Expected Get operation failure, got: " << msg;
    std::cout << "Non-existent secret error details verified" << std::endl;
  }
}

// Test: op_all with max_ids=0 returns no results
TEST_F(KmipClientIntegrationTest20, GetAllIdsWithZeroLimitReturnsEmpty) {
  auto kmip = createKmipClient();
  try {
    auto ids =
        kmip->client().op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0);
    EXPECT_TRUE(ids.empty());
  } catch (kmipcore::KmipException &e) {
    FAIL() << "GetAllIdsWithZeroLimit (2.0) failed: " << e.what();
  }
}

TEST_F(KmipClientIntegrationTest20, GetAllIdsPageWithZeroPageSizeReturnsEmpty) {
  auto kmip = createKmipClient();
  try {
    std::optional<std::size_t> located_items = 1;
    auto page = kmip->client().op_all_page(
        object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 0, &located_items
    );
    EXPECT_TRUE(page.empty());
    EXPECT_FALSE(located_items.has_value());
  } catch (kmipcore::KmipException &e) {
    FAIL() << "GetAllIdsPageWithZeroPageSizeReturnsEmpty (2.0) failed: "
           << e.what();
  }
}

TEST_F(KmipClientIntegrationTest20, GetAllIdsPageMatchesUngroupedLocatePage) {
  auto kmip = createKmipClient();
  try {
    std::optional<std::size_t> all_located_items;
    auto all_page = kmip->client().op_all_page(
        object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 8, &all_located_items
    );

    std::optional<std::size_t> locate_located_items;
    auto locate_page = kmip->client().op_locate_page_by_group(
        "", object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 8, &locate_located_items
    );

    EXPECT_EQ(all_page, locate_page);
    EXPECT_EQ(all_located_items, locate_located_items);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "GetAllIdsPageMatchesUngroupedLocatePage (2.0) failed: "
           << e.what();
  }
}

// Test: op_all includes newly created keys
TEST_F(KmipClientIntegrationTest20, GetAllIdsIncludesCreatedKeys) {
  auto kmip = createKmipClient();
  std::vector<std::string> created;
  try {
    for (int i = 0; i < 3; ++i) {
      const auto id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "GetAllIds_" + std::to_string(i), TEST_GROUP
      );
      created.push_back(id);
      trackForCleanup(id);
    }

    constexpr std::size_t kDefaultSearchCap =
        MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH;
    constexpr std::size_t kFallbackSearchCap = kDefaultSearchCap * 4;

    std::optional<std::size_t> located_items;
    (void) kmip->client().op_all_page(
        object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 1, &located_items
    );

    std::size_t max_ids = located_items.has_value()
                            ? std::max(kDefaultSearchCap, *located_items)
                            : kFallbackSearchCap;
    auto all =
        kmip->client().op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, max_ids);

    std::vector<std::string> missing_ids;
    for (const auto &cid : created) {
      if (std::find(all.begin(), all.end(), cid) == all.end()) {
        missing_ids.push_back(cid);
      }
    }

    if (!missing_ids.empty()) {
      auto group_ids = kmip->client().op_locate_by_group(
          TEST_GROUP,
          object_type::KMIP_OBJTYPE_SYMMETRIC_KEY,
          kFallbackSearchCap
      );
      bool all_missing_found_by_group = true;
      for (const auto &cid : missing_ids) {
        if (std::find(group_ids.begin(), group_ids.end(), cid) ==
            group_ids.end()) {
          all_missing_found_by_group = false;
          break;
        }
      }

      if (all_missing_found_by_group) {
        GTEST_SKIP() << "Server omits some keys from ungrouped Locate/op_all, "
                        "but group-filtered Locate finds them";
      }
    }

    for (const auto &cid : missing_ids) {
      ADD_FAILURE() << "Created id " << cid << " not found in op_all";
    }
    std::cout << "op_all includes all " << created.size() << " created key(s)"
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "GetAllIdsIncludesCreatedKeys (2.0) failed: " << e.what();
  }
}

// Test: Duplicate-name keys yield distinct IDs and are both locatable
TEST_F(KmipClientIntegrationTest20, CreateDuplicateNames) {
  auto kmip = createKmipClient();
  const std::string name = TESTING_NAME_PREFIX + "DuplicateName";
  std::string id1, id2;
  try {
    id1 = kmip->client().op_create_aes_key(name, TEST_GROUP);
    id2 = kmip->client().op_create_aes_key(name, TEST_GROUP);
    trackForCleanup(id1);
    trackForCleanup(id2);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Create duplicate names (2.0) failed: " << e.what();
  }

  ASSERT_FALSE(id1.empty());
  ASSERT_FALSE(id2.empty());
  EXPECT_NE(id1, id2) << "Duplicate-name keys must have unique IDs";

  try {
    auto found = kmip->client().op_locate_by_name(
        name, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY
    );
    EXPECT_NE(std::find(found.begin(), found.end(), id1), found.end())
        << "First key not found by name";
    EXPECT_NE(std::find(found.begin(), found.end(), id2), found.end())
        << "Second key not found by name";
    std::cout << "Both duplicate-name keys found by name" << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Locate duplicate names (2.0) failed: " << e.what();
  }
}

// Test: set_protocol_version switches from 1.4 default to 2.0 at runtime
TEST_F(KmipClientIntegrationTest20, SetProtocolVersionSwitchesTo20) {
  auto &config = KmipTestConfig20::getInstance();

  // Start at 1.4, but use local-friendly TLS settings for 127.0.0.1.
  Kmip kmip14(
      config.kmip_addr.c_str(),
      config.kmip_port.c_str(),
      config.kmip_client_ca.c_str(),
      config.kmip_client_key.c_str(),
      config.kmip_server_ca.c_str(),
      config.timeout_ms,
      kmipcore::KMIP_VERSION_1_4,
      nullptr,
      NetClient::TlsVerificationOptions{
          .peer_verification = true,
          .hostname_verification = false,
      }
  );

  EXPECT_EQ(kmip14.client().protocol_version().getMajor(), 1);
  EXPECT_EQ(kmip14.client().protocol_version().getMinor(), 4);

  // Switch to 2.0 and issue a request that uses the new encoding.
  kmip14.client().set_protocol_version(kmipcore::KMIP_VERSION_2_0);
  EXPECT_EQ(kmip14.client().protocol_version().getMajor(), 2);
  EXPECT_EQ(kmip14.client().protocol_version().getMinor(), 0);

  try {
    const auto id = kmip14.client().op_create_aes_key(
        TESTING_NAME_PREFIX + "SetVersion20", TEST_GROUP
    );
    EXPECT_FALSE(id.empty());
    trackForCleanup(id);
    std::cout << "Created key after runtime version switch to 2.0: " << id
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "CreateAES after set_protocol_version(2.0) failed: " << e.what();
  }
}

// NOTE: main() is defined in KmipClientIntegrationTest.cpp which is compiled
// into the same kmipclient_test binary.  KmipTestConfig20 prints its own
// diagnostic banner to stderr during static initialisation when the required
// environment variables are absent.
