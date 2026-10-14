/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmiputil/KeyGenerator.hpp"

#include <gtest/gtest.h>

namespace {

  using kmipclient::aes_key_size;
  using kmiputil::KeyGenerator;

  TEST(KeyGeneratorTest, GeneratesAesKeysOfEachSize) {
    for (const auto size : {
             aes_key_size::AES_128, aes_key_size::AES_192, aes_key_size::AES_256
         }) {
      const auto key = KeyGenerator::generate_aes(size);
      const auto bits = static_cast<int32_t>(size);
      EXPECT_EQ(key.type(), kmipclient::KeyType::SYMMETRIC_KEY);
      EXPECT_EQ(key.value().size(), static_cast<size_t>(bits / 8));
      EXPECT_EQ(
          key.algorithm(),
          kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_AES
      );
      EXPECT_EQ(key.crypto_length(), bits);
    }
  }

  TEST(KeyGeneratorTest, DefaultsToAes256) {
    EXPECT_EQ(KeyGenerator::generate_aes().value().size(), 32u);
  }

  TEST(KeyGeneratorTest, GeneratesDifferentKeys) {
    EXPECT_NE(
        KeyGenerator::generate_aes().value(),
        KeyGenerator::generate_aes().value()
    );
  }

}  // namespace
