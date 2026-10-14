/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_OPENSSL_UTILS_HPP
#define KMIPUTIL_OPENSSL_UTILS_HPP

#include <memory>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <span>
#include <string>

namespace kmiputil::detail {

  struct BioDeleter {
    void operator()(BIO *bio) const noexcept { BIO_free(bio); }
  };
  using BioPtr = std::unique_ptr<BIO, BioDeleter>;

  /**
   * Owns a DER buffer allocated by an OpenSSL `i2d_*` call and clears +
   * frees it on destruction, including when an exception unwinds past it
   * while the buffer still holds key material.
   */
  class DerBuffer {
  public:
    // der/len as returned by i2d_*: der may be non-null with len <= 0 on
    // failure, so operator bool() checks both.
    DerBuffer(unsigned char *der, int len) noexcept : der_(der), len_(len) {}
    DerBuffer(const DerBuffer &) = delete;
    DerBuffer &operator=(const DerBuffer &) = delete;
    ~DerBuffer() {
      OPENSSL_clear_free(der_, len_ > 0 ? static_cast<size_t>(len_) : 0);
    }

    explicit operator bool() const noexcept { return len_ > 0; }

    std::span<const unsigned char> span() const noexcept {
      return {der_, static_cast<size_t>(len_)};
    }

  private:
    unsigned char *der_;
    int len_;
  };

  /** Text of the most recent OpenSSL error; clears the thread's error queue.
   */
  inline std::string openssl_error() {
    const unsigned long err = ERR_peek_last_error();
    ERR_clear_error();
    if (err == 0) {
      return "unknown error";
    }
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return buf;
  }

}  // namespace kmiputil::detail

#endif  // KMIPUTIL_OPENSSL_UTILS_HPP
