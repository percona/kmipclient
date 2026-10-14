/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmiputil/KeyGenerator.hpp"

#include "AesKey.hpp"
#include "OpenSSLUtils.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/secure_memory.hpp"

#include <openssl/rand.h>

namespace kmiputil {

  kmipclient::SymmetricKey
      KeyGenerator::generate_aes(kmipclient::aes_key_size key_size) {
    const size_t size_bytes = static_cast<size_t>(key_size) / 8;
    kmipcore::secure_bytes buf(size_bytes);
    if (1 != RAND_bytes(buf.data(), static_cast<int>(size_bytes))) {
      throw kmipcore::KmipException(
          "OpenSSL RAND_bytes failed: " + detail::openssl_error()
      );
    }

    return detail::make_aes_key(buf);
  }

}  // namespace kmiputil
