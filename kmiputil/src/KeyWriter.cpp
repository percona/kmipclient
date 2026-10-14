/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmiputil/KeyWriter.hpp"

#include "Encoding.hpp"
#include "OpenSSLUtils.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <climits>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace kmiputil {

  namespace {

    struct X509Deleter {
      void operator()(X509 *x) const noexcept { X509_free(x); }
    };
    struct PkeyDeleter {
      void operator()(EVP_PKEY *k) const noexcept { EVP_PKEY_free(k); }
    };

    constexpr size_t kPemLineLength = 64;

    [[noreturn]] void throw_invalid(const char *what) {
      throw kmipcore::KmipException(
          std::string("Cannot write ") + what +
          " as PEM: " + detail::openssl_error()
      );
    }

    kmipcore::secure_string bio_contents(BIO *bio) {
      char *data = nullptr;
      const long len = BIO_get_mem_data(bio, &data);
      if (len <= 0 || !data) {
        throw kmipcore::KmipException("PEM encoding produced no output");
      }
      return kmipcore::secure_string(data, static_cast<size_t>(len));
    }

    // BIO_s_secmem keeps the PEM text in OpenSSL secure memory and clears it
    // on free, which matters for private keys.
    detail::BioPtr new_secure_bio() {
      detail::BioPtr bio(BIO_new(BIO_s_secmem()));
      if (!bio) {
        throw kmipcore::KmipException("Failed to create BIO for PEM output");
      }
      return bio;
    }

    kmipcore::secure_string certificate_to_pem(const kmipclient::Key &key) {
      // Isolate this call's errors from whatever a previous, unrelated
      // OpenSSL call may have left in the thread's error queue, so
      // throw_invalid() below never reports a stale error as its own.
      ERR_clear_error();
      const kmipcore::secure_bytes &der = key.value();
      std::unique_ptr<X509, X509Deleter> cert;
      {
        const unsigned char *p = der.data();
        if (!der.empty() && der.size() <= LONG_MAX) {
          cert.reset(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
        }
        if (!cert || p != der.data() + der.size()) {
          throw_invalid("certificate");
        }
      }
      auto bio = new_secure_bio();
      if (1 != PEM_write_bio_X509(bio.get(), cert.get())) {
        throw_invalid("certificate");
      }
      return bio_contents(bio.get());
    }

    kmipcore::secure_string private_key_to_pem(const kmipclient::Key &key) {
      ERR_clear_error();
      const kmipcore::secure_bytes &der = key.value();
      std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey;
      {
        const unsigned char *p = der.data();
        if (!der.empty() && der.size() <= LONG_MAX) {
          // Accepts both the type-specific DER that KeyReader stores and
          // PKCS#8 PrivateKeyInfo.
          pkey.reset(
              d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(der.size()))
          );
        }
        if (!pkey || p != der.data() + der.size()) {
          throw_invalid("private key");
        }
      }
      auto bio = new_secure_bio();
      if (1 != PEM_write_bio_PrivateKey(
                   bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr
               )) {
        throw_invalid("private key");
      }
      return bio_contents(bio.get());
    }

    kmipcore::secure_string public_key_to_pem(const kmipclient::Key &key) {
      ERR_clear_error();
      const kmipcore::secure_bytes &der = key.value();
      const long len = static_cast<long>(der.size());
      std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey;
      if (!der.empty() && der.size() <= LONG_MAX) {
        // SubjectPublicKeyInfo (what KeyReader stores), then a bare PKCS#1
        // RSAPublicKey, which servers return for the PKCS#1 key format.
        const unsigned char *p = der.data();
        pkey.reset(d2i_PUBKEY(nullptr, &p, len));
        if (pkey && p != der.data() + der.size()) {
          pkey.reset();
        }
        if (!pkey) {
          ERR_clear_error();
          p = der.data();
          pkey.reset(d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, len));
          if (pkey && p != der.data() + der.size()) {
            pkey.reset();
          }
        }
      }
      if (!pkey) {
        throw_invalid("public key");
      }
      auto bio = new_secure_bio();
      if (1 != PEM_write_bio_PUBKEY(bio.get(), pkey.get())) {
        throw_invalid("public key");
      }
      return bio_contents(bio.get());
    }

    kmipcore::secure_string symmetric_key_to_pem(const kmipclient::Key &key) {
      if (key.value().empty()) {
        throw kmipcore::KmipException(
            "Cannot write symmetric key as PEM: empty key material"
        );
      }
      const kmipcore::secure_string b64 = encoding::to_base64(key.value());
      kmipcore::secure_string pem;
      // b64 plus a newline every kPemLineLength chars, plus the header/footer
      // lines; avoids reallocating (and re-scrubbing) the secure buffer as
      // it grows.
      pem.reserve(b64.size() + b64.size() / kPemLineLength + 64);
      pem.append("-----BEGIN SYMMETRIC KEY-----\n");
      for (size_t pos = 0; pos < b64.size(); pos += kPemLineLength) {
        pem.append(b64, pos, kPemLineLength);
        pem.push_back('\n');
      }
      pem.append("-----END SYMMETRIC KEY-----\n");
      return pem;
    }

  }  // namespace

  kmipcore::secure_string KeyWriter::to_hex(const kmipclient::Key &key) {
    return encoding::to_hex(key.value());
  }

  kmipcore::secure_string KeyWriter::to_base64(const kmipclient::Key &key) {
    return encoding::to_base64(key.value());
  }

  kmipcore::secure_string KeyWriter::to_PEM(const kmipclient::Key &key) {
    switch (key.type()) {
      case kmipclient::KeyType::CERTIFICATE:
        return certificate_to_pem(key);
      case kmipclient::KeyType::PRIVATE_KEY:
        return private_key_to_pem(key);
      case kmipclient::KeyType::PUBLIC_KEY:
        return public_key_to_pem(key);
      case kmipclient::KeyType::SYMMETRIC_KEY:
        return symmetric_key_to_pem(key);
      case kmipclient::KeyType::UNSET:
      default:
        throw kmipcore::KmipException(
            "Cannot write key as PEM: unsupported key type"
        );
    }
  }

}  // namespace kmiputil
