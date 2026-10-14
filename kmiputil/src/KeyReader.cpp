/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmiputil/KeyReader.hpp"

#include "AesKey.hpp"
#include "Encoding.hpp"
#include "OpenSSLUtils.hpp"
#include "kmipclient/PrivateKey.hpp"
#include "kmipclient/PublicKey.hpp"
#include "kmipclient/X509Certificate.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/secure_memory.hpp"

#include <climits>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string>

namespace kmiputil {

  namespace {

    // Without a callback OpenSSL prompts on the terminal for the passphrase of
    // an encrypted key. A library must not do that, so refuse instead.
    int no_passphrase(char *, int, int, void *) {
      return -1;
    }

    std::unique_ptr<kmipclient::Key> try_parse_x509_certificate(BIO *bio) {
      X509 *cert = PEM_read_bio_X509(bio, nullptr, no_passphrase, nullptr);
      if (!cert) {
        return nullptr;
      }

      unsigned char *der = nullptr;
      const int len = i2d_X509(cert, &der);
      const detail::DerBuffer buf(der, len);
      X509_free(cert);
      if (!buf) {
        return nullptr;
      }

      kmipcore::Attributes attrs;
      attrs.set(kmipclient::KMIP_ATTR_NAME_NAME, "certificate");
      return std::make_unique<kmipclient::X509Certificate>(
          buf.span(), std::move(attrs)
      );
    }

    std::unique_ptr<kmipclient::Key> try_parse_private_key(BIO *bio) {
      EVP_PKEY *pkey =
          PEM_read_bio_PrivateKey(bio, nullptr, no_passphrase, nullptr);
      if (!pkey) {
        return nullptr;
      }

      unsigned char *der = nullptr;
      const int len = i2d_PrivateKey(pkey, &der);
      const detail::DerBuffer buf(der, len);
      EVP_PKEY_free(pkey);
      if (!buf) {
        return nullptr;
      }

      kmipcore::Attributes attrs;
      attrs.set(kmipclient::KMIP_ATTR_NAME_NAME, "private_key");
      return std::make_unique<kmipclient::PrivateKey>(
          buf.span(), std::move(attrs)
      );
    }

    std::unique_ptr<kmipclient::Key> try_parse_public_key(BIO *bio) {
      EVP_PKEY *pkey =
          PEM_read_bio_PUBKEY(bio, nullptr, no_passphrase, nullptr);
      if (!pkey) {
        return nullptr;
      }

      unsigned char *der = nullptr;
      const int len = i2d_PUBKEY(pkey, &der);
      const detail::DerBuffer buf(der, len);
      EVP_PKEY_free(pkey);
      if (!buf) {
        return nullptr;
      }

      kmipcore::Attributes attrs;
      attrs.set(kmipclient::KMIP_ATTR_NAME_NAME, "public_key");
      return std::make_unique<kmipclient::PublicKey>(
          buf.span(), std::move(attrs)
      );
    }

    // Label matches what KeyWriter::to_PEM writes for a symmetric key; there
    // is no standard PEM type for raw key material, so any other label (an
    // encrypted private key, say) must not be reinterpreted as an AES key
    // just because its body happens to decode to an AES key length.
    constexpr std::string_view kSymmetricKeyBegin =
        "-----BEGIN SYMMETRIC KEY-----";
    constexpr std::string_view kSymmetricKeyEnd = "-----END SYMMETRIC KEY-----";

    std::unique_ptr<kmipclient::Key>
        try_parse_aes_from_pem_text(std::string_view pem) {
      kmipcore::secure_string b64;
      bool in_pem = false;
      while (!pem.empty()) {
        const size_t eol = pem.find('\n');
        const std::string_view line = pem.substr(0, eol);
        pem.remove_prefix(eol == std::string_view::npos ? pem.size() : eol + 1);

        if (!in_pem) {
          in_pem = line == kSymmetricKeyBegin;
          continue;
        }
        if (line == kSymmetricKeyEnd) {
          break;
        }
        b64.append(line);
      }

      if (b64.empty()) {
        return nullptr;
      }

      try {
        return std::make_unique<kmipclient::SymmetricKey>(
            KeyReader::aes_from_base64(b64)
        );
      } catch (const kmipcore::KmipException &) {
        return nullptr;
      }
    }

  }  // namespace

  kmipclient::SymmetricKey KeyReader::aes_from_hex(std::string_view hex) {
    return detail::make_aes_key(encoding::from_hex(hex));
  }

  kmipclient::SymmetricKey KeyReader::aes_from_base64(std::string_view base64) {
    return detail::make_aes_key(encoding::from_base64(base64));
  }

  kmipclient::SymmetricKey
      KeyReader::aes_from_value(std::span<const unsigned char> value) {
    return detail::make_aes_key(value);
  }

  std::unique_ptr<kmipclient::Key> KeyReader::from_PEM(std::string_view pem) {
    if (pem.size() > INT_MAX) {
      throw kmipcore::KmipException("PEM data is too large");
    }
    const detail::BioPtr bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))
    );
    if (!bio) {
      throw kmipcore::KmipException("Failed to create BIO for PEM data");
    }

    // Each failed attempt leaves errors in the thread's OpenSSL error queue;
    // clear them so they are not mistaken for errors of later TLS calls.
    for (auto parse :
         {try_parse_x509_certificate,
          try_parse_private_key,
          try_parse_public_key}) {
      if (auto key = parse(bio.get())) {
        return key;
      }
      ERR_clear_error();
      (void) BIO_reset(bio.get());
    }

    if (auto key = try_parse_aes_from_pem_text(pem)) {
      return key;
    }

    throw kmipcore::KmipException(
        kmipcore::KMIP_NOT_IMPLEMENTED,
        "Unsupported PEM format or not implemented"
    );
  }

}  // namespace kmiputil
