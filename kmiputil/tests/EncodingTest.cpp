/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "Encoding.hpp"

#include "kmipcore/kmip_errors.hpp"

#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

namespace {

  using kmiputil::encoding::from_base64;
  using kmiputil::encoding::from_hex;
  using kmiputil::encoding::to_base64;
  using kmiputil::encoding::to_hex;

  std::vector<unsigned char> bytes_of(std::string_view s) {
    return {s.begin(), s.end()};
  }

  TEST(EncodingTest, HexRoundTrip) {
    const std::vector<unsigned char> bytes{0x00, 0x01, 0x7f, 0x80, 0xab, 0xff};
    EXPECT_EQ(to_hex(bytes), "00017f80abff");
    EXPECT_EQ(from_hex("00017f80abff"), bytes);
    EXPECT_EQ(from_hex("00017F80ABFF"), bytes);
  }

  TEST(EncodingTest, HexRejectsInvalidInput) {
    EXPECT_THROW((void) from_hex(""), kmipcore::KmipException);
    EXPECT_THROW((void) from_hex("abc"), kmipcore::KmipException);
    EXPECT_THROW((void) from_hex("zz"), kmipcore::KmipException);
  }

  // RFC 4648, section 10.
  TEST(EncodingTest, Base64TestVectors) {
    const std::vector<std::pair<std::string, std::string>> vectors{
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    };
    for (const auto &[plain, encoded] : vectors) {
      EXPECT_EQ(to_base64(bytes_of(plain)), encoded) << plain;
      EXPECT_EQ(from_base64(encoded), bytes_of(plain)) << encoded;
    }
  }

  TEST(EncodingTest, Base64DecodeSkipsLineBreaks) {
    EXPECT_EQ(from_base64("Zm9v\nYmFy\r\n"), bytes_of("foobar"));
  }

}  // namespace
