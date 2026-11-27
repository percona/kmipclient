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

    [[noreturn]] void throw_invalid(
        const char *what, const detail::OpenSslErrorScope &errors
    ) {
      throw kmipcore::KmipException(
          std::string("Cannot write ") + what +
          " as PEM: " + errors.last_error()
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

    // BIO_s_secmem clears the PEM text when its buffer grows or is freed,
    // which matters for private keys. It also places the buffer in OpenSSL's
    // secure heap, but only if the application set one up with
    // CRYPTO_secure_malloc_init(); otherwise it uses the normal heap.
    detail::BioPtr new_secure_bio() {
      detail::BioPtr bio(BIO_new(BIO_s_secmem()));
      if (!bio) {
        throw kmipcore::KmipException("Failed to create BIO for PEM output");
      }
      return bio;
    }

    kmipcore::secure_string certificate_to_pem(const kmipclient::Key &key) {
      const detail::OpenSslErrorScope errors;
      const kmipcore::secure_bytes &der = key.value();
      std::unique_ptr<X509, X509Deleter> cert;
      {
        const unsigned char *p = der.data();
        if (!der.empty() && der.size() <= LONG_MAX) {
          cert.reset(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
        }
        if (!cert || p != der.data() + der.size()) {
          throw_invalid("certificate", errors);
        }
      }
      auto bio = new_secure_bio();
      if (1 != PEM_write_bio_X509(bio.get(), cert.get())) {
        throw_invalid("certificate", errors);
      }
      return bio_contents(bio.get());
    }

    kmipcore::secure_string private_key_to_pem(const kmipclient::Key &key) {
      const detail::OpenSslErrorScope errors;
      const kmipcore::secure_bytes &der = key.value();
      std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey;
      {
        const unsigned char *p = der.data();
        if (!der.empty() && der.size() <= LONG_MAX) {
          // Accepts both PKCS#8 PrivateKeyInfo (what KeyReader stores) and
          // the per-algorithm DER, e.g. PKCS#1 for RSA.
          pkey.reset(
              d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(der.size()))
          );
        }
        if (!pkey || p != der.data() + der.size()) {
          throw_invalid("private key", errors);
        }
      }
      auto bio = new_secure_bio();
      if (1 != PEM_write_bio_PrivateKey(
                   bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr
               )) {
        throw_invalid("private key", errors);
      }
      return bio_contents(bio.get());
    }

    kmipcore::secure_string public_key_to_pem(const kmipclient::Key &key) {
      detail::OpenSslErrorScope errors;
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
          errors.reset();
          p = der.data();
          pkey.reset(d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, len));
          if (pkey && p != der.data() + der.size()) {
            pkey.reset();
          }
        }
      }
      if (!pkey) {
        throw_invalid("public key", errors);
      }
      auto bio = new_secure_bio();
      if (1 != PEM_write_bio_PUBKEY(bio.get(), pkey.get())) {
        throw_invalid("public key", errors);
      }
      return bio_contents(bio.get());
    }

    // KeyReader::from_PEM reads SYMMETRIC KEY text back as an AES key, so
    // writing any other symmetric key (HMAC, say) would come back as AES or
    // not at all. Refuse those rather than write PEM that misreads.
    bool is_aes_key(const kmipclient::Key &key) {
      const size_t size = key.value().size();
      return key.algorithm() ==
                 kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_AES &&
             (size == 16 || size == 24 || size == 32);
    }

    kmipcore::secure_string symmetric_key_to_pem(const kmipclient::Key &key) {
      if (!is_aes_key(key)) {
        throw kmipcore::KmipException(
            "Cannot write symmetric key as PEM: only 128, 192 or 256-bit AES "
            "keys are supported"
        );
      }
      // An AES key is at most 44 Base64 characters, well within PEM's
      // 64-column lines, so the body is a single line.
      const kmipcore::secure_string b64 = encoding::to_base64(key.value());
      kmipcore::secure_string pem;
      // Header, body and footer; avoids reallocating (and re-scrubbing) the
      // secure buffer as it grows.
      pem.reserve(b64.size() + 64);
      pem.append("-----BEGIN SYMMETRIC KEY-----\n");
      pem.append(b64);
      pem.append("\n-----END SYMMETRIC KEY-----\n");
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
      default:
        throw kmipcore::KmipException(
            "Cannot write key as PEM: unsupported key type"
        );
    }
  }

}  // namespace kmiputil
