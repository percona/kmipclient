/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "AesKey.hpp"

#include "kmipcore/kmip_errors.hpp"

#include <string>

namespace kmiputil::detail {

  kmipclient::SymmetricKey make_aes_key(std::span<const unsigned char> bytes) {
    const size_t size = bytes.size();
    if (size != 16 && size != 24 && size != 32) {
      throw kmipcore::KmipException{
          -1,
          std::string("Invalid AES key length: ") + std::to_string(size * 8) +
              " bits. Should be 128, 192 or 256 bits"
      };
    }

    kmipcore::Attributes attrs;
    attrs.set_algorithm(kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_AES)
        .set_crypto_length(static_cast<int32_t>(size * 8))
        // CryptographicUsageMask is required by strict servers (e.g. Vault).
        // ENCRYPT|DECRYPT is the correct default for a symmetric AES key.
        .set_usage_mask(
            static_cast<kmipclient::cryptographic_usage_mask>(
                kmipcore::KMIP_CRYPTOMASK_ENCRYPT |
                kmipcore::KMIP_CRYPTOMASK_DECRYPT
            )
        );

    return kmipclient::SymmetricKey(bytes, std::move(attrs));
  }

}  // namespace kmiputil::detail
