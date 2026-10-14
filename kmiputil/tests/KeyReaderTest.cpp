/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmiputil/KeyReader.hpp"

#include "TestPem.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/secure_memory.hpp"

#include <gtest/gtest.h>
#include <openssl/err.h>
#include <vector>

namespace {

  using kmipclient::KeyType;
  using kmiputil::KeyReader;

  constexpr std::string_view kAes128Hex = "000102030405060708090a0b0c0d0e0f";

  void expect_aes(const kmipclient::Key &key, size_t bytes) {
    EXPECT_EQ(key.type(), KeyType::SYMMETRIC_KEY);
    EXPECT_EQ(key.value().size(), bytes);
    EXPECT_EQ(
        key.algorithm(), kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_AES
    );
    EXPECT_EQ(key.crypto_length(), static_cast<int32_t>(bytes * 8));
    EXPECT_EQ(
        static_cast<uint32_t>(key.usage_mask()),
        static_cast<uint32_t>(
            kmipcore::KMIP_CRYPTOMASK_ENCRYPT |
            kmipcore::KMIP_CRYPTOMASK_DECRYPT
        )
    );
  }

  TEST(KeyReaderTest, AesFromHexOfEachSize) {
    expect_aes(KeyReader::aes_from_hex(kAes128Hex), 16);
    expect_aes(KeyReader::aes_from_hex(std::string(48, 'a')), 24);
    expect_aes(KeyReader::aes_from_hex(std::string(64, 'F')), 32);
  }

  TEST(KeyReaderTest, AesFromHexKeepsTheBytes) {
    const auto key = KeyReader::aes_from_hex(kAes128Hex);
    for (size_t i = 0; i < key.value().size(); ++i) {
      EXPECT_EQ(key.value()[i], i);
    }
  }

  TEST(KeyReaderTest, AesRejectsWrongLengthOrBadInput) {
    EXPECT_THROW(
        (void) KeyReader::aes_from_hex("000102"), kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyReader::aes_from_hex(std::string(32, 'g')),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyReader::aes_from_value(std::vector<unsigned char>(17)),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyReader::aes_from_value(std::vector<unsigned char>{}),
        kmipcore::KmipException
    );
  }

  TEST(KeyReaderTest, AesFromBase64AndValueAgree) {
    const std::vector<unsigned char> raw(32, 0x5a);
    const auto from_value = KeyReader::aes_from_value(raw);
    const auto from_b64 = KeyReader::aes_from_base64(
        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo="
    );
    expect_aes(from_value, 32);
    EXPECT_EQ(from_value.value(), raw);
    EXPECT_EQ(from_b64.value(), raw);
  }

  TEST(KeyReaderTest, AesFromValueTakesSecureBytes) {
    const kmipcore::secure_bytes raw(16, 0x11);
    EXPECT_EQ(KeyReader::aes_from_value(raw).value(), raw);
  }

  TEST(KeyReaderTest, PemCertificate) {
    const auto key = KeyReader::from_PEM(kmiputil_test::kCertificate);
    EXPECT_EQ(key->type(), KeyType::CERTIFICATE);
    EXPECT_FALSE(key->value().empty());
    EXPECT_EQ(
        key->attribute_value(kmipclient::KMIP_ATTR_NAME_NAME), "certificate"
    );
  }

  TEST(KeyReaderTest, PemPrivateKeyInBothFormats) {
    const auto pkcs8 = KeyReader::from_PEM(kmiputil_test::kEcPrivateKeyPkcs8);
    const auto traditional =
        KeyReader::from_PEM(kmiputil_test::kEcPrivateKeyTraditional);
    EXPECT_EQ(pkcs8->type(), KeyType::PRIVATE_KEY);
    EXPECT_EQ(traditional->type(), KeyType::PRIVATE_KEY);
    EXPECT_EQ(pkcs8->value(), traditional->value());
    EXPECT_EQ(
        pkcs8->attribute_value(kmipclient::KMIP_ATTR_NAME_NAME), "private_key"
    );
  }

  TEST(KeyReaderTest, PemPublicKey) {
    const auto key = KeyReader::from_PEM(kmiputil_test::kEcPublicKey);
    EXPECT_EQ(key->type(), KeyType::PUBLIC_KEY);
    EXPECT_FALSE(key->value().empty());
    EXPECT_EQ(
        key->attribute_value(kmipclient::KMIP_ATTR_NAME_NAME), "public_key"
    );
  }

  TEST(KeyReaderTest, PemSymmetricKeyText) {
    const auto key = KeyReader::from_PEM(
        "-----BEGIN SYMMETRIC KEY-----\n"
        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=\n"
        "-----END SYMMETRIC KEY-----\n"
    );
    expect_aes(*key, 32);
    EXPECT_EQ(key->value(), std::vector<unsigned char>(32, 0x5a));
  }

  // A non-SYMMETRIC-KEY label must not be reinterpreted as an AES key, even
  // when its body happens to decode to a valid AES key length.
  TEST(KeyReaderTest, PemWrongLabelIsNotReadAsSymmetricKey) {
    EXPECT_THROW(
        (void) KeyReader::from_PEM(
            "-----BEGIN NOT A KEY-----\n"
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=\n"
            "-----END NOT A KEY-----\n"
        ),
        kmipcore::KmipException
    );
  }

  // Must fail rather than prompt on the terminal for the passphrase.
  TEST(KeyReaderTest, PemEncryptedPrivateKeyIsRejected) {
    EXPECT_THROW(
        (void) KeyReader::from_PEM(kmiputil_test::kEncryptedPrivateKey),
        kmipcore::KmipException
    );
  }

  TEST(KeyReaderTest, PemGarbageIsRejected) {
    EXPECT_THROW((void) KeyReader::from_PEM(""), kmipcore::KmipException);
    EXPECT_THROW(
        (void) KeyReader::from_PEM("not a pem"), kmipcore::KmipException
    );
  }

  // Failed parse attempts must not leave errors behind for later TLS calls.
  TEST(KeyReaderTest, PemLeavesOpenSSLErrorQueueEmpty) {
    ERR_clear_error();
    (void) KeyReader::from_PEM(kmiputil_test::kEcPublicKey);
    EXPECT_EQ(ERR_peek_error(), 0u);
  }

}  // namespace
