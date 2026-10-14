/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmiputil/KeyWriter.hpp"

#include "TestPem.hpp"
#include "kmipclient/PrivateKey.hpp"
#include "kmipclient/PublicKey.hpp"
#include "kmipclient/X509Certificate.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmiputil/KeyReader.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string>
#include <vector>

namespace {

  using kmipclient::KeyType;
  using kmiputil::KeyReader;
  using kmiputil::KeyWriter;

  std::string as_string(const kmipcore::secure_string &s) {
    return {s.begin(), s.end()};
  }

  void expect_pem_round_trip(const kmipclient::Key &key, const char *label) {
    const std::string pem = as_string(KeyWriter::to_PEM(key));
    EXPECT_TRUE(pem.starts_with(std::string("-----BEGIN ") + label + "-----\n"))
        << pem;
    const auto back = KeyReader::from_PEM(pem);
    EXPECT_EQ(back->type(), key.type());
    EXPECT_EQ(back->value(), key.value());
  }

  TEST(KeyWriterTest, HexAndBase64) {
    const auto key =
        KeyReader::aes_from_hex("000102030405060708090a0b0c0d0e0f");
    EXPECT_EQ(KeyWriter::to_hex(key), "000102030405060708090a0b0c0d0e0f");
    EXPECT_EQ(KeyWriter::to_base64(key), "AAECAwQFBgcICQoLDA0ODw==");
    EXPECT_EQ(
        KeyReader::aes_from_base64(as_string(KeyWriter::to_base64(key)))
            .value(),
        key.value()
    );
  }

  TEST(KeyWriterTest, CertificatePemMatchesInput) {
    const auto key = KeyReader::from_PEM(kmiputil_test::kCertificate);
    EXPECT_EQ(as_string(KeyWriter::to_PEM(*key)), kmiputil_test::kCertificate);
    expect_pem_round_trip(*key, "CERTIFICATE");
  }

  TEST(KeyWriterTest, PublicKeyPemMatchesInput) {
    const auto key = KeyReader::from_PEM(kmiputil_test::kEcPublicKey);
    EXPECT_EQ(as_string(KeyWriter::to_PEM(*key)), kmiputil_test::kEcPublicKey);
    expect_pem_round_trip(*key, "PUBLIC KEY");
  }

  TEST(KeyWriterTest, PrivateKeyIsWrittenAsPkcs8) {
    const auto key =
        KeyReader::from_PEM(kmiputil_test::kEcPrivateKeyTraditional);
    expect_pem_round_trip(*key, "PRIVATE KEY");
  }

  TEST(KeyWriterTest, SymmetricKeyPemUses64ColumnLines) {
    // 32 bytes encode to 44 Base64 characters: a single line.
    const auto key =
        KeyReader::aes_from_value(std::vector<unsigned char>(32, 1));
    const std::string pem = as_string(KeyWriter::to_PEM(key));
    EXPECT_EQ(
        pem,
        "-----BEGIN SYMMETRIC KEY-----\n"
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"
        "-----END SYMMETRIC KEY-----\n"
    );
    expect_pem_round_trip(key, "SYMMETRIC KEY");
  }

  TEST(KeyWriterTest, SymmetricKeyPemWrapsLongMaterial) {
    const kmipclient::SymmetricKey key(std::vector<unsigned char>(64, 2));
    const std::string pem = as_string(KeyWriter::to_PEM(key));
    size_t start = pem.find('\n') + 1;
    const size_t end = pem.find("-----END");
    while (start < end) {
      const size_t eol = pem.find('\n', start);
      EXPECT_LE(eol - start, 64u);
      start = eol + 1;
    }
  }

  // Servers return RSA public keys as bare PKCS#1 RSAPublicKey when asked for
  // that key format; the writer turns them into SubjectPublicKeyInfo.
  TEST(KeyWriterTest, RsaPkcs1PublicKey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    ASSERT_NE(ctx, nullptr);
    EVP_PKEY *raw = nullptr;
    ASSERT_EQ(EVP_PKEY_keygen_init(ctx), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048), 1);
    ASSERT_EQ(EVP_PKEY_keygen(ctx, &raw), 1);
    EVP_PKEY_CTX_free(ctx);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        raw, EVP_PKEY_free
    );

    // i2d_* allocate the output; copy it out and free it.
    auto take_der = [](unsigned char *der, int len) {
      std::vector<unsigned char> v(der, der + len);
      OPENSSL_free(der);
      return v;
    };
    unsigned char *der = nullptr;
    int len = i2d_PublicKey(pkey.get(), &der);
    ASSERT_GT(len, 0);
    const auto pkcs1 = take_der(der, len);
    der = nullptr;
    len = i2d_PUBKEY(pkey.get(), &der);
    ASSERT_GT(len, 0);
    const auto spki = take_der(der, len);

    const std::string pem =
        as_string(KeyWriter::to_PEM(kmipclient::PublicKey(pkcs1)));
    EXPECT_TRUE(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    EXPECT_EQ(KeyReader::from_PEM(pem)->value(), spki);
  }

  TEST(KeyWriterTest, RejectsMaterialThatDoesNotMatchTheType) {
    const std::vector<unsigned char> junk{0x01, 0x02, 0x03};
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(kmipclient::PrivateKey(junk)),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(kmipclient::PublicKey(junk)),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(kmipclient::X509Certificate(junk)),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(
            kmipclient::SymmetricKey(std::vector<unsigned char>{})
        ),
        kmipcore::KmipException
    );
  }

  TEST(KeyWriterTest, RejectsTrailingBytesAfterCertificate) {
    const auto cert = KeyReader::from_PEM(kmiputil_test::kCertificate);
    std::vector<unsigned char> der(cert->value().begin(), cert->value().end());
    der.push_back(0);
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(kmipclient::X509Certificate(der)),
        kmipcore::KmipException
    );
  }

}  // namespace
