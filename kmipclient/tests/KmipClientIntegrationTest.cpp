/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "TestEnvUtils.hpp"
#include "kmipclient/Kmip.hpp"
#include "kmipclient/KmipClient.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_errors.hpp"
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
#include <utility>
#include <vector>

#define TEST_GROUP "tests"

using namespace kmipclient;

static std::string TESTING_NAME_PREFIX = "tests_";

// Helper class to manage environment variables
class KmipTestConfig {
public:
  static KmipTestConfig &getInstance() {
    static KmipTestConfig instance;
    return instance;
  }

  [[nodiscard]] bool isConfigured() const {
    return !kmip_addr.empty() && !kmip_port.empty() &&
           !kmip_client_ca.empty() && !kmip_client_key.empty() &&
           !kmip_server_ca.empty();
  }

  std::string kmip_addr;
  std::string kmip_port;
  std::string kmip_client_ca;
  std::string kmip_client_key;
  std::string kmip_server_ca;
  int timeout_ms;
  bool run_2_0_tests;

private:
  KmipTestConfig() {
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

    timeout_ms = 5000;  // Default 5 seconds
    if (timeout) {
      errno = 0;
      char *end = nullptr;
      const long parsed = std::strtol(timeout, &end, 10);
      if (errno == 0 && end != timeout && *end == '\0' && parsed >= 0 &&
          parsed <= INT_MAX) {
        timeout_ms = static_cast<int>(parsed);
      }
    }

    run_2_0_tests = kmipclient::test::is_env_flag_enabled("KMIP_RUN_2_0_TESTS");

    if (!isConfigured()) {
      std::cerr << "WARNING: KMIP environment variables not set. Tests will be "
                   "skipped.\n"
                << "Required variables:\n"
                << "  KMIP_ADDR\n"
                << "  KMIP_PORT\n"
                << "  KMIP_CLIENT_CA\n"
                << "  KMIP_CLIENT_KEY\n"
                << "  KMIP_SERVER_CA\n";
    }
  }
};

// Base test fixture for KMIP integration tests
class KmipClientIntegrationTest : public ::testing::Test {
protected:
  std::vector<std::string> created_key_ids;

  void SetUp() override {
    auto &config = KmipTestConfig::getInstance();

    if (!config.isConfigured()) {
      GTEST_SKIP() << "KMIP 1.4: environment variables not configured";
    }

    try {
      auto kmip = createKmipClient();
      // Use a minimal request to surface transport/auth issues with context.
      (void) kmip->client().op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0);
    } catch (const std::exception &e) {
      GTEST_SKIP() << "KMIP 1.4: server connectivity check failed: "
                   << e.what();
    }
  }

  void TearDown() override {
    const auto *test_info =
        ::testing::UnitTest::GetInstance()->current_test_info();
    if (HasFailure()) {
      std::cout << test_info->name() << ": FAIL" << std::endl;
    } else {
      std::cout << test_info->name() << ": OK" << std::endl;
    }

    // Cleanup created keys if stored
    auto &config = KmipTestConfig::getInstance();
    if (config.isConfigured() && !created_key_ids.empty()) {
      try {
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

        for (const auto &key_id : created_key_ids) {
          // Try to destroy the key (best effort cleanup)
          try {
            // if the object is not active then it cannot be revoked with reason
            // other than revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE
            auto res_r = kmip.client().op_revoke(
                key_id,
                revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE,
                "Test cleanup",
                0
            );
            auto res_d = kmip.client().op_destroy(key_id);
          } catch (kmipcore::KmipException &e) {
            std::cerr << "Failed to destroy key: " << e.what() << std::endl;
          }
        }
      } catch (...) {
        // Ignore cleanup errors
      }
    }
  }

  static std::unique_ptr<Kmip> createKmipClient() {
    auto &config = KmipTestConfig::getInstance();
    try {
      return std::make_unique<Kmip>(
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
    } catch (const std::exception &e) {
      throw std::runtime_error(
          "Failed to initialize KMIP client for " + config.kmip_addr + ":" +
          config.kmip_port + " (client cert: " + config.kmip_client_ca +
          ", client key: " + config.kmip_client_key +
          ", server cert: " + config.kmip_server_ca + "): " + e.what()
      );
    }
  }

  void trackKeyForCleanup(const std::string &key_id) {
    created_key_ids.push_back(key_id);
  }
};

TEST_F(KmipClientIntegrationTest, NetClientOpenSSLCanRetryAfterFailedConnect) {
  auto &config = KmipTestConfig::getInstance();

  NetClientOpenSSL net_client(
      config.kmip_addr,
      config.kmip_port,
      config.kmip_client_ca,
      config.kmip_client_key,
      config.kmip_server_ca,
      config.timeout_ms
  );

  bool first_connect_failed = false;
  try {
    (void) net_client.connect();
  } catch (const kmipcore::KmipException &) {
    first_connect_failed = true;
  }

  if (!first_connect_failed) {
    net_client.close();
    GTEST_SKIP() << "KMIP 1.4: environment does not produce a post-BIO "
                    "connect failure "
                    "for configured host '"
                 << config.kmip_addr << "'; skipping retry regression test";
  }

  EXPECT_FALSE(net_client.is_connected());

  net_client.set_tls_verification({
      .peer_verification = true,
      .hostname_verification = false,
  });

  try {
    ASSERT_TRUE(net_client.connect());
  } catch (const kmipcore::KmipException &e) {
    // Some environments cannot complete the second connection attempt against
    // the configured endpoint, so retry behavior is not observable.
    GTEST_SKIP() << "KMIP 1.4: retry path is not testable in this "
                    "environment: "
                 << config.kmip_addr << ":" << config.kmip_port << ": "
                 << e.what();
  }
  EXPECT_TRUE(net_client.is_connected());

  KmipClient client(net_client, {}, kmipcore::KMIP_VERSION_1_4, false);
  EXPECT_NO_THROW(
      (void) client.op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0)
  );

  net_client.close();
  EXPECT_FALSE(net_client.is_connected());
}

TEST_F(
    KmipClientIntegrationTest, MoveConstructedKmipSupportsReadOnlyOperation
) {
  auto kmip = createKmipClient();

  Kmip moved_kmip(std::move(*kmip));

  EXPECT_NO_THROW((void) moved_kmip.client().op_all(
      object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0
  ));
}

TEST_F(KmipClientIntegrationTest, MoveConstructedKmipCanCreateAndGetKey) {
  auto kmip = createKmipClient();
  Kmip moved_kmip(std::move(*kmip));

  try {
    const auto key_id = moved_kmip.client().op_create_aes_key(
        TESTING_NAME_PREFIX + "MoveConstructedKmipCanCreateAndGetKey",
        TEST_GROUP
    );
    ASSERT_FALSE(key_id.empty());
    trackKeyForCleanup(key_id);

    auto key = moved_kmip.client().op_get_key(key_id);
    ASSERT_NE(key, nullptr);
    EXPECT_EQ(key->value().size(), 32);
  } catch (const kmipcore::KmipException &e) {
    FAIL() << "MoveConstructedKmipCanCreateAndGetKey failed: " << e.what();
  }
}

// Test: Locate keys by group
TEST_F(KmipClientIntegrationTest, LocateKeysByGroup) {
  auto kmip = createKmipClient();
  std::string group_name =
      "test_locate_group_" + std::to_string(std::time(nullptr));
  std::vector<std::string> expected_ids;

  try {
    // Create a few keys in the same unique group
    for (int i = 0; i < 3; ++i) {
      auto key_id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocateByGroup_" + std::to_string(i), group_name
      );
      expected_ids.push_back(key_id);
      trackKeyForCleanup(key_id);
    }

    // Locate by group
    auto found_ids = kmip->client().op_locate_by_group(
        group_name, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY
    );

    // Verify all created keys are found
    for (const auto &expected_id : expected_ids) {
      auto it = std::find(found_ids.begin(), found_ids.end(), expected_id);
      EXPECT_NE(it, found_ids.end())
          << "Key " << expected_id << " not found in group " << group_name;
    }

    std::cout << "Successfully located " << expected_ids.size()
              << " keys in group: " << group_name << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Locate by group failed: " << e.what();
  }
}

TEST_F(
    KmipClientIntegrationTest, LocatePageByGroupSinglePageReturnsExpectedIds
) {
  auto kmip = createKmipClient();
  std::string group_name =
      "test_locate_page_group_" + std::to_string(std::time(nullptr));
  std::vector<std::string> created_ids;

  try {
    for (int i = 0; i < 3; ++i) {
      auto key_id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocatePageByGroup_" + std::to_string(i),
          group_name
      );
      created_ids.push_back(key_id);
      trackKeyForCleanup(key_id);
    }

    std::optional<std::size_t> located_items;
    auto page = kmip->client().op_locate_page_by_group(
        group_name,
        object_type::KMIP_OBJTYPE_SYMMETRIC_KEY,
        0,
        2,
        &located_items
    );

    EXPECT_EQ(page.size(), 2u);
    for (const auto &id : page) {
      EXPECT_NE(
          std::find(created_ids.begin(), created_ids.end(), id),
          created_ids.end()
      );
    }
  } catch (kmipcore::KmipException &e) {
    FAIL() << "LocatePageByGroupSinglePageReturnsExpectedIds failed: "
           << e.what();
  }
}

TEST_F(
    KmipClientIntegrationTest,
    LocatePageByGroupIteratesDeterministicallyWithOffset
) {
  auto kmip = createKmipClient();
  std::string group_name =
      "test_locate_page_iter_" + std::to_string(std::time(nullptr));
  std::vector<std::string> created_ids;

  try {
    for (int i = 0; i < 5; ++i) {
      auto key_id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocatePageIter_" + std::to_string(i),
          group_name
      );
      created_ids.push_back(key_id);
      trackKeyForCleanup(key_id);
    }

    std::optional<std::size_t> first_located_items;
    auto first_page = kmip->client().op_locate_page_by_group(
        group_name,
        object_type::KMIP_OBJTYPE_SYMMETRIC_KEY,
        0,
        2,
        &first_located_items
    );
    auto first_page_repeat = kmip->client().op_locate_page_by_group(
        group_name, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 2, nullptr
    );
    ASSERT_FALSE(first_page.empty());
    EXPECT_EQ(first_page, first_page_repeat);

    std::vector<std::string> paged_ids = first_page;
    std::vector<std::string> previous_page = first_page;
    std::size_t offset = first_page.size();
    bool offset_honored = false;
    for (std::size_t i = 0; i < 8; ++i) {
      auto page = kmip->client().op_locate_page_by_group(
          group_name,
          object_type::KMIP_OBJTYPE_SYMMETRIC_KEY,
          offset,
          2,
          nullptr
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

    auto one_shot_ids = kmip->client().op_locate_by_group(
        group_name, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, created_ids.size()
    );
    if (offset_honored) {
      EXPECT_EQ(paged_ids, one_shot_ids);
    } else {
      EXPECT_GE(one_shot_ids.size(), first_page.size());
      EXPECT_EQ(
          std::vector<std::string>(
              one_shot_ids.begin(),
              one_shot_ids.begin() +
                  static_cast<std::ptrdiff_t>(first_page.size())
          ),
          first_page
      );
    }
    for (const auto &id : paged_ids) {
      EXPECT_NE(
          std::find(one_shot_ids.begin(), one_shot_ids.end(), id),
          one_shot_ids.end()
      );
    }
    for (const auto &id : created_ids) {
      EXPECT_NE(
          std::find(one_shot_ids.begin(), one_shot_ids.end(), id),
          one_shot_ids.end()
      );
    }
  } catch (kmipcore::KmipException &e) {
    FAIL() << "LocatePageByGroupIteratesDeterministicallyWithOffset failed: "
           << e.what();
  }
}

TEST_F(
    KmipClientIntegrationTest,
    LocatePageByGroupReportsLocatedItemsWhenServerProvidesIt
) {
  auto kmip = createKmipClient();
  std::string group_name =
      "test_locate_page_total_" + std::to_string(std::time(nullptr));
  const auto &protocol_version = kmip->client().protocol_version();

  try {
    for (int i = 0; i < 2; ++i) {
      auto key_id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocatePageTotal_" + std::to_string(i),
          group_name
      );
      trackKeyForCleanup(key_id);
    }

    std::optional<std::size_t> located_items;
    auto page = kmip->client().op_locate_page_by_group(
        group_name,
        object_type::KMIP_OBJTYPE_SYMMETRIC_KEY,
        0,
        10,
        &located_items
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
    KmipClientIntegrationTest, LocatePageByGroupWithZeroPageSizeReturnsEmpty
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
    FAIL() << "LocatePageByGroupWithZeroPageSizeReturnsEmpty failed: "
           << e.what();
  }
}

// Test: op_locate_by_group respects max_ids upper bound
TEST_F(KmipClientIntegrationTest, LocateKeysByGroupHonorsMaxIds) {
  auto kmip = createKmipClient();
  std::string group_name =
      "test_locate_group_limit_" + std::to_string(std::time(nullptr));
  std::vector<std::string> created_ids;

  try {
    for (int i = 0; i < 3; ++i) {
      auto key_id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "LocateByGroupLimit_" + std::to_string(i),
          group_name
      );
      created_ids.push_back(key_id);
      trackKeyForCleanup(key_id);
    }

    const size_t max_ids = 2;
    auto found_ids = kmip->client().op_locate_by_group(
        group_name, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, max_ids
    );

    EXPECT_LE(found_ids.size(), max_ids);
    EXPECT_EQ(found_ids.size(), max_ids);
    for (const auto &id : found_ids) {
      auto it = std::find(created_ids.begin(), created_ids.end(), id);
      EXPECT_NE(it, created_ids.end())
          << "Located id " << id << " was not created by this test";
    }
  } catch (kmipcore::KmipException &e) {
    FAIL() << "LocateKeysByGroupHonorsMaxIds failed: " << e.what();
  }
}

// Test: op_all with max_ids=0 returns no ids
TEST_F(KmipClientIntegrationTest, GetAllIdsWithZeroLimitReturnsEmpty) {
  auto kmip = createKmipClient();
  try {
    auto all_ids =
        kmip->client().op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0);
    EXPECT_TRUE(all_ids.empty());
  } catch (kmipcore::KmipException &e) {
    FAIL() << "GetAllIdsWithZeroLimitReturnsEmpty failed: " << e.what();
  }
}

TEST_F(KmipClientIntegrationTest, GetAllIdsPageWithZeroPageSizeReturnsEmpty) {
  auto kmip = createKmipClient();
  try {
    std::optional<std::size_t> located_items = 1;
    auto page = kmip->client().op_all_page(
        object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 0, 0, &located_items
    );
    EXPECT_TRUE(page.empty());
    EXPECT_FALSE(located_items.has_value());
  } catch (kmipcore::KmipException &e) {
    FAIL() << "GetAllIdsPageWithZeroPageSizeReturnsEmpty failed: " << e.what();
  }
}

TEST_F(KmipClientIntegrationTest, GetAllIdsPageMatchesUngroupedLocatePage) {
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
    FAIL() << "GetAllIdsPageMatchesUngroupedLocatePage failed: " << e.what();
  }
}

// Test: Create symmetric AES key
TEST_F(KmipClientIntegrationTest, CreateSymmetricAESKey) {
  auto kmip = createKmipClient();

  try {
    const std::string key_id_128 = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "CreateSymmetricAESKey128",
        TEST_GROUP,
        aes_key_size::AES_128
    );
    const std::string key_id_256 = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "CreateSymmetricAESKey256",
        TEST_GROUP,
        aes_key_size::AES_256
    );

    trackKeyForCleanup(key_id_128);
    trackKeyForCleanup(key_id_256);

    auto key_128 = kmip->client().op_get_key(key_id_128);
    auto key_256 = kmip->client().op_get_key(key_id_256);

    EXPECT_EQ(key_128->value().size(), 16);  // 128 bits
    EXPECT_EQ(key_256->value().size(), 32);  // 256 bits

    std::cout << "Created AES-128 key ID: " << key_id_128
              << ", AES-256 key ID: " << key_id_256 << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to create key: " << e.what();
  }
}

// Test: Create and Get key
TEST_F(KmipClientIntegrationTest, CreateAndGetKey) {
  auto kmip = createKmipClient();
  std::string key_id;
  // Create key
  try {
    key_id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "CreateAndGetKey", TEST_GROUP
    );
    trackKeyForCleanup(key_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to create key: " << e.what();
  }

  // Get key
  try {
    auto key = kmip->client().op_get_key(key_id);
    EXPECT_FALSE(key->value().empty());
    EXPECT_EQ(key->value().size(), 32);  // 256 bits = 32 bytes
    std::cout << "Retrieved key with " << key->value().size() << " bytes"
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to get key: " << e.what();
  }
}

// Test: Create, Activate, and Get key
TEST_F(KmipClientIntegrationTest, CreateActivateAndGetKey) {
  auto kmip = createKmipClient();
  std::string key_id;
  // Create key
  try {
    key_id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "CreateActivateAndGetKey", TEST_GROUP
    );
    trackKeyForCleanup(key_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to create key: " << e.what();
  }
  // Activate key
  try {
    auto active_id = kmip->client().op_activate(key_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to activate key: " << e.what();
  }

  // Get key and it's state
  try {
    auto get_result = kmip->client().op_get_key(key_id);
    ASSERT_FALSE(get_result->value().empty())
        << "Failed to get activated key: " << key_id;
    auto attrs =
        kmip->client().op_get_attributes(key_id, {KMIP_ATTR_NAME_STATE});
    auto state_value = attrs.object_state();
    EXPECT_TRUE(state_value == state::KMIP_STATE_ACTIVE)
        << "State is not ACTIVE for key: " << key_id;
    std::cout << "Successfully activated and retrieved key: " << key_id
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to activate key: " << e.what();
  }
}

// Test: Register symmetric key
TEST_F(KmipClientIntegrationTest, RegisterSymmetricKey) {
  auto kmip = createKmipClient();

  // Create a test key value
  std::vector<unsigned char> key_value = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  };
  try {
    auto key_id = kmip->client().op_register_key(
        TESTING_NAME_PREFIX + "RegisterSymmetricKey",
        TEST_GROUP,
        kmiputil::KeyReader::aes_from_value(key_value)
    );
    EXPECT_FALSE(key_id.empty());
    std::cout << "Registered key with ID: " << key_id << std::endl;
    trackKeyForCleanup(key_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to register key: " << e.what();
  }
}

// Test: Register symmetric key, then activate it explicitly
TEST_F(KmipClientIntegrationTest, RegisterThenActivateSymmetricKey) {
  auto kmip = createKmipClient();

  std::vector<unsigned char> key_value = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  };

  std::string key_id;
  try {
    key_id = kmip->client().op_register_key(
        TESTING_NAME_PREFIX + "RegisterThenActivateSymmetricKey",
        TEST_GROUP,
        kmiputil::KeyReader::aes_from_value(key_value)
    );
    ASSERT_FALSE(key_id.empty());
    trackKeyForCleanup(key_id);
    const auto activated_id = kmip->client().op_activate(key_id);
    EXPECT_EQ(activated_id, key_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "RegisterThenActivateSymmetricKey failed: " << e.what();
  }

  try {
    auto key = kmip->client().op_get_key(key_id);
    ASSERT_FALSE(key->value().empty());
    auto attrs =
        kmip->client().op_get_attributes(key_id, {KMIP_ATTR_NAME_STATE});
    EXPECT_EQ(attrs.object_state(), state::KMIP_STATE_ACTIVE)
        << "Key should be ACTIVE immediately after explicit activate";
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Get after RegisterThenActivateSymmetricKey failed: " << e.what();
  }
}

// Test: Register secret, then activate it explicitly
TEST_F(KmipClientIntegrationTest, RegisterThenActivateSecret) {
  auto kmip = createKmipClient();

  const std::vector<unsigned char> secret_data = {'s', 'e', 'c', 'r', 'e', 't'};
  kmipcore::Attributes secret_attrs;
  secret_attrs.set_state(state::KMIP_STATE_PRE_ACTIVE);
  const Secret secret(
      secret_data, secret_data_type::KMIP_SECDATA_PASSWORD, secret_attrs
  );

  std::string secret_id;
  try {
    secret_id = kmip->client().op_register_secret(
        TESTING_NAME_PREFIX + "RegisterThenActivateSecret", TEST_GROUP, secret
    );
    ASSERT_FALSE(secret_id.empty());
    trackKeyForCleanup(secret_id);
    const auto activated_id = kmip->client().op_activate(secret_id);
    EXPECT_EQ(activated_id, secret_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "RegisterThenActivateSecret failed: " << e.what();
  }

  try {
    auto retrieved_secret = kmip->client().op_get_secret(secret_id, true);
    EXPECT_EQ(retrieved_secret.value(), secret_data);
    EXPECT_EQ(retrieved_secret.get_state(), state::KMIP_STATE_ACTIVE);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Get after RegisterThenActivateSecret failed: " << e.what();
  }
}

// Test: Register secret data
TEST_F(KmipClientIntegrationTest, RegisterAndGetSecret) {
  auto kmip = createKmipClient();
  std::string secret_id;
  std::vector<unsigned char> secret_data = {'s', 'e', 'c', 'r', 'e', 't'};
  kmipcore::Attributes secret_attrs;
  secret_attrs.set_state(state::KMIP_STATE_PRE_ACTIVE);
  Secret secret(
      secret_data, secret_data_type::KMIP_SECDATA_PASSWORD, secret_attrs
  );
  try {
    secret_id = kmip->client().op_register_secret(
        TESTING_NAME_PREFIX + "a_secret", TEST_GROUP, secret
    );
    EXPECT_FALSE(secret_id.empty());
    std::cout << "Registered secret with ID: " << secret_id << std::endl;
    trackKeyForCleanup(secret_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Registered secret failed: " << e.what();
  }

  try {
    auto activated_id = kmip->client().op_activate(secret_id);
    EXPECT_EQ(activated_id, secret_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to activate secret: " << e.what();
  }

  try {
    auto retrieved_secret = kmip->client().op_get_secret(secret_id, true);
    EXPECT_EQ(retrieved_secret.value().size(), secret_data.size());
    EXPECT_EQ(retrieved_secret.value(), secret_data);
    // Check that attributes exist - Name or State or any other typed/generic
    // attribute
    EXPECT_TRUE(
        retrieved_secret.attributes().has_attribute(KMIP_ATTR_NAME_NAME) ||
        retrieved_secret.attributes().has_attribute("Name") ||
        !retrieved_secret.attributes().generic().empty()
    );

    // Check State attribute
    auto state_value = retrieved_secret.attributes().object_state();
    EXPECT_EQ(state_value, state::KMIP_STATE_ACTIVE);
    EXPECT_EQ(retrieved_secret.get_state(), state::KMIP_STATE_ACTIVE);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Get secret failed: " << e.what();
  }
}

// Test: Locate keys
TEST_F(KmipClientIntegrationTest, LocateKeys) {
  auto kmip = createKmipClient();
  std::string key_id;
  std::vector<std::string> result;
  std::string name = TESTING_NAME_PREFIX + "LocateKeys";
  // Create key
  try {
    key_id = kmip->client().op_create_aes_key(name, TEST_GROUP);
    trackKeyForCleanup(key_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to create key: " << e.what();
  }
  // Find by name
  try {
    auto fkey_ids = kmip->client().op_locate_by_name(
        name, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY
    );
    // At least the key we just created must be returned.
    // (PyKMIP accumulates stale keys across runs so historically size() > 1
    // was checked; Vault enforces unique names so there is always exactly 1.)
    ASSERT_FALSE(fkey_ids.empty())
        << "Locate by name returned no results for key: " << key_id;
    auto it = std::find(fkey_ids.begin(), fkey_ids.end(), key_id);
    EXPECT_NE(it, fkey_ids.end())
        << "Created key " << key_id << " not found by name";
    std::cout << "Found " << fkey_ids.size() << " keys" << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to find a key: " << e.what();
  }
}

// Test: Get attributes
TEST_F(KmipClientIntegrationTest, CreateAndGetAttributes) {
  auto kmip = createKmipClient();
  std::string key_id;
  std::string name = TESTING_NAME_PREFIX + "CreateAndGetAttributes";
  // Create key
  try {
    key_id = kmip->client().op_create_aes_key(name, TEST_GROUP);
    trackKeyForCleanup(key_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to create key: " << e.what();
  }

  // Get attributes
  try {
    auto attr_result =
        kmip->client().op_get_attributes(key_id, {KMIP_ATTR_NAME_NAME});
    attr_result.merge(
        kmip->client().op_get_attributes(key_id, {KMIP_ATTR_NAME_GROUP})
    );
    auto attr_name = attr_result.get(KMIP_ATTR_NAME_NAME);
    auto attr_group = attr_result.get(KMIP_ATTR_NAME_GROUP);
    std::cout << "Successfully retrieved attributes for key: " << key_id
              << std::endl;
    EXPECT_EQ(name, attr_name);
    EXPECT_EQ(TEST_GROUP, attr_group);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to get a key attribute: " << e.what();
  }
}

// Test: Revoke key
TEST_F(KmipClientIntegrationTest, CreateAndRevokeKey) {
  auto kmip = createKmipClient();

  // Create and activate key
  std::string key_id;
  std::string name = TESTING_NAME_PREFIX + "CreateAndRevokeKey";
  // Create key
  try {
    key_id = kmip->client().op_create_aes_key(name, TEST_GROUP);
    trackKeyForCleanup(key_id);
    auto activate_result = kmip->client().op_activate(key_id);
    EXPECT_EQ(activate_result, key_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to create key: " << e.what();
  }

  // Revoke key
  try {
    auto revoke_result = kmip->client().op_revoke(
        key_id,
        revocation_reason_type::KMIP_REVOKE_UNSPECIFIED,
        "Test revocation",
        0
    );
    std::cout << "Successfully revoked key: " << key_id << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to revoke key: " << e.what();
  }
}

// Test: Full lifecycle - Create, Activate, Get, Revoke, Destroy
TEST_F(KmipClientIntegrationTest, FullKeyLifecycle) {
  auto kmip = createKmipClient();
  try {
    // Create
    auto key_id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "FullKeyLifecycle", TEST_GROUP
    );
    std::cout << "1. Created key: " << key_id << std::endl;

    // Activate
    auto activate_result = kmip->client().op_activate(key_id);
    ASSERT_FALSE(activate_result.empty()) << "Activate failed: ";
    std::cout << "2. Activated key" << std::endl;

    // Get
    auto get_result = kmip->client().op_get_key(key_id);
    ASSERT_FALSE(get_result->value().empty()) << "Get failed: ";
    std::cout << "3. Retrieved key" << std::endl;

    // Revoke
    auto revoke_result = kmip->client().op_revoke(
        key_id,
        revocation_reason_type::KMIP_REVOKE_UNSPECIFIED,
        "Test lifecycle",
        0
    );
    ASSERT_FALSE(revoke_result.empty()) << "Revoke failed";
    std::cout << "4. Revoked key" << std::endl;

    // Destroy
    auto destroy_result = kmip->client().op_destroy(key_id);
    ASSERT_TRUE(destroy_result == key_id) << "Destroy failed";
    std::cout << "5. Destroyed key" << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed full life cycle of key: " << e.what();
  }
  // Don't track for cleanup since we already destroyed it
}

// Test: Get non-existent key should fail
TEST_F(KmipClientIntegrationTest, GetNonExistentKey) {
  auto kmip = createKmipClient();
  const std::string fake_id = "non-existent-key-id-12345";

  try {
    auto key = kmip->client().op_get_key(fake_id);
    (void) key;
    FAIL() << "Should fail to get non-existent key";
  } catch (const kmipcore::KmipException &e) {
    const std::string msg = e.what();
    EXPECT_NE(msg.find("Operation: Get"), std::string::npos)
        << "Expected Get operation failure path, got: " << msg;
    EXPECT_NE(msg.find("Result reason:"), std::string::npos)
        << "Expected server Result Reason in error, got: " << msg;
    std::cout << "Successfully verified non-existent key returns server "
                 "error details"
              << std::endl;
  }
}

TEST_F(KmipClientIntegrationTest, GetNonExistentSecret) {
  auto kmip = createKmipClient();
  const std::string fake_id = "non-existent-secret-id-12345";

  try {
    auto secret = kmip->client().op_get_secret(fake_id);
    (void) secret;
    FAIL() << "Should fail to get non-existent secret";
  } catch (const kmipcore::KmipException &e) {
    const std::string msg = e.what();
    EXPECT_NE(msg.find("Operation: Get"), std::string::npos)
        << "Expected Get operation failure path, got: " << msg;
    std::cout << "Successfully verified non-existent secret cannot be "
                 "retrieved"
              << std::endl;
  }
}

// Test: Multiple keys creation
TEST_F(KmipClientIntegrationTest, CreateMultipleKeys) {
  auto kmip = createKmipClient();

  constexpr int num_keys = 3;
  std::vector<std::string> key_ids;
  try {
    for (int i = 0; i < num_keys; ++i) {
      auto result = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "_CreateMultipleKeys_" + std::to_string(i),
          TEST_GROUP
      );
      ASSERT_FALSE(result.empty()) << "Failed to create key " << i;

      key_ids.push_back(result);
      trackKeyForCleanup(result);
    }

    EXPECT_EQ(key_ids.size(), num_keys);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Multiple keys creation failed" << e.what();
  }
  // Verify all keys are different
  for (size_t i = 0; i < key_ids.size(); ++i) {
    for (size_t j = i + 1; j < key_ids.size(); ++j) {
      EXPECT_NE(key_ids[i], key_ids[j]) << "Keys should have unique IDs";
    }
  }

  std::cout << "Successfully created " << num_keys << " unique keys"
            << std::endl;
}

// Test: Destroying a key removes it (cannot be retrieved)
TEST_F(KmipClientIntegrationTest, DestroyKeyRemovesKey) {
  auto kmip = createKmipClient();
  std::string key_id;
  try {
    key_id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "DestroyKeyRemovesKey", TEST_GROUP
    );
    ASSERT_FALSE(key_id.empty());
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to create key for destroy test: " << e.what();
  }

  // Destroy the key
  try {
    auto destroy_result = kmip->client().op_destroy(key_id);
    ASSERT_EQ(destroy_result, key_id)
        << "Destroy did not return the expected id";
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to destroy key: " << e.what();
  }

  // Attempt to get the destroyed key - should not be retrievable
  try {
    auto key = kmip->client().op_get_key(key_id);
    EXPECT_TRUE(key->value().empty())
        << "Destroyed key should not be retrievable";
  } catch (kmipcore::KmipException &) {
    // Some servers respond with an error for non-existent objects; this is
    // acceptable
    SUCCEED();
  }

  std::cout << "Successfully verified destroyed key is not retrievable"
            << std::endl;
}

// Test: Creating two keys with the same name should yield distinct IDs and both
// should be locatable
TEST_F(KmipClientIntegrationTest, CreateDuplicateNames) {
  auto kmip = createKmipClient();
  // Use a timestamp suffix so each test run gets a fresh name and does not
  // collide with a stale key left by a previous (possibly failed) run.
  std::string name = TESTING_NAME_PREFIX + "DuplicateNameTest_" +
                     std::to_string(std::time(nullptr));
  std::string id1, id2;
  try {
    id1 = kmip->client().op_create_aes_key(name, TEST_GROUP);
    trackKeyForCleanup(id1);
  } catch (kmipcore::KmipException &e) {
    // If a key with this name already exists the server enforces uniqueness.
    GTEST_SKIP() << "KMIP 1.4: server enforces unique names (first Create "
                    "rejected): "
                 << e.what();
  }

  try {
    id2 = kmip->client().op_create_aes_key(name, TEST_GROUP);
    trackKeyForCleanup(id2);
  } catch (kmipcore::KmipException &e) {
    // HashiCorp Vault (and other strict KMIP servers) enforce globally unique
    // names and reject a second Create with the same name.  Skip instead of
    // failing so the test suite still shows this as "not supported" rather than
    // a hard error.  PyKMIP allows duplicate names.
    GTEST_SKIP() << "KMIP 1.4: server enforces unique names (duplicate "
                    "Create rejected): "
                 << e.what();
  }

  ASSERT_FALSE(id1.empty());
  ASSERT_FALSE(id2.empty());
  EXPECT_NE(id1, id2) << "Duplicate name keys should have unique IDs";

  try {
    auto found = kmip->client().op_locate_by_name(
        name, object_type::KMIP_OBJTYPE_SYMMETRIC_KEY
    );
    // Both created IDs should be present
    auto it1 = std::find(found.begin(), found.end(), id1);
    auto it2 = std::find(found.begin(), found.end(), id2);
    EXPECT_NE(it1, found.end()) << "First key not found by name";
    EXPECT_NE(it2, found.end()) << "Second key not found by name";
    std::cout << "Successfully verified duplicate names yield unique IDs"
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Locate by name failed for duplicate names: " << e.what();
  }
}

// Test: Revoke changes state to REVOKED
TEST_F(KmipClientIntegrationTest, RevokeChangesState) {
  auto kmip = createKmipClient();
  std::string key_id;
  try {
    key_id = kmip->client().op_create_aes_key(
        TESTING_NAME_PREFIX + "RevokeChangesState", TEST_GROUP
    );
    trackKeyForCleanup(key_id);
    auto activate_res = kmip->client().op_activate(key_id);
    EXPECT_EQ(activate_res, key_id);
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to create/activate key for revoke test: " << e.what();
  }

  try {
    auto revoke_res = kmip->client().op_revoke(
        key_id,
        revocation_reason_type::KMIP_REVOKE_UNSPECIFIED,
        "Test revoke state",
        0
    );
    EXPECT_FALSE(revoke_res.empty());
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to revoke key: " << e.what();
  }

  try {
    auto attrs =
        kmip->client().op_get_attributes(key_id, {KMIP_ATTR_NAME_STATE});
    auto state_value = attrs.object_state();
    EXPECT_TRUE(state_value == state::KMIP_STATE_DEACTIVATED)
        << "Expected DEACTIVATED state";
    std::cout << "Successfully verified key state changed to DEACTIVATED"
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed to get attributes after revoke: " << e.what();
  }
}

// Test: op_get_all_ids should include newly created keys of the requested
// object type
TEST_F(KmipClientIntegrationTest, GetAllIdsIncludesCreatedKeys) {
  auto kmip = createKmipClient();
  std::vector<std::string> created_ids;
  try {
    for (int i = 0; i < 5; ++i) {
      auto id = kmip->client().op_create_aes_key(
          TESTING_NAME_PREFIX + "GetAllIds_" + std::to_string(i), TEST_GROUP
      );
      created_ids.push_back(id);
      trackKeyForCleanup(id);
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
    auto all_ids =
        kmip->client().op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, max_ids);

    std::vector<std::string> missing_ids;
    for (const auto &cid : created_ids) {
      if (std::find(all_ids.begin(), all_ids.end(), cid) == all_ids.end()) {
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
      ADD_FAILURE() << "Created id " << cid << " not found in op_get_all_ids";
    }
    std::cout << "Successfully verified " << created_ids.size()
              << " created keys are in op_all results" << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "GetAllIdsIncludesCreatedKeys failed: " << e.what();
  }
}

// Test: Register a symmetric key and verify its NAME attribute
TEST_F(KmipClientIntegrationTest, RegisterKeyAndGetAttributes) {
  auto kmip = createKmipClient();
  std::string name = TESTING_NAME_PREFIX + "RegisterKeyAttrs";
  try {
    // Use a deterministic 256-bit (32 byte) key value for registration
    std::vector<unsigned char> key_value = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    auto key = kmiputil::KeyReader::aes_from_value(key_value);
    const auto expected_mask = static_cast<cryptographic_usage_mask>(
        kmipcore::KMIP_CRYPTOMASK_ENCRYPT | kmipcore::KMIP_CRYPTOMASK_DECRYPT |
        kmipcore::KMIP_CRYPTOMASK_MAC_GENERATE
    );
    key.attributes().set_usage_mask(expected_mask);

    auto key_id = kmip->client().op_register_key(name, TEST_GROUP, key);
    EXPECT_FALSE(key_id.empty());
    trackKeyForCleanup(key_id);

    auto attrs = kmip->client().op_get_attributes(
        key_id, {KMIP_ATTR_NAME_NAME, KMIP_ATTR_NAME_CRYPTO_USAGE_MASK}
    );
    const auto &attr_name = attrs.get(KMIP_ATTR_NAME_NAME);
    EXPECT_EQ(attr_name, name);
    // Servers may add compatible usage bits (for example MAC_VERIFY when
    // MAC_GENERATE is requested). Require at least the requested bits.
    const auto actual_mask_u32 = static_cast<std::uint32_t>(attrs.usage_mask());
    const auto expected_mask_u32 = static_cast<std::uint32_t>(expected_mask);
    EXPECT_EQ((actual_mask_u32 & expected_mask_u32), expected_mask_u32);
    std::cout << "Successfully verified registered key attributes match"
              << std::endl;
  } catch (kmipcore::KmipException &e) {
    FAIL() << "RegisterKeyAndGetAttributes failed: " << e.what();
  }
}

// Main function
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  // Disable test shuffling
  ::testing::GTEST_FLAG(shuffle) = false;

  // Get configuration
  auto &config = KmipTestConfig::getInstance();

  // Check if KMIP 2.0 tests should be skipped
  if (!config.run_2_0_tests) {
    // Exclude the entire KMIP 2.0 test suite if env var is not set
    ::testing::GTEST_FLAG(filter) = "-KmipClientIntegrationTest20.*";
    std::cout << "INFO: KMIP_RUN_2_0_TESTS is not set. "
              << "KMIP 2.0 tests will not run.\n"
              << "Set KMIP_RUN_2_0_TESTS=1 to enable the KMIP 2.0 suite.\n"
              << std::endl;
  }

  // Print configuration
  if (config.isConfigured()) {
    std::cout << "KMIP Test Configuration:\n"
              << "  Server: " << config.kmip_addr << ":" << config.kmip_port
              << "\n"
              << "  Client CA: " << config.kmip_client_ca << "\n"
              << "  Client Key: " << config.kmip_client_key << "\n"
              << "  Server CA: " << config.kmip_server_ca << "\n"
              << "  Timeout: " << config.timeout_ms << "ms\n"
              << "  KMIP 2.0 Tests: "
              << (config.run_2_0_tests ? "ENABLED" : "DISABLED") << "\n"
              << std::endl;
  }
  return RUN_ALL_TESTS();
}
