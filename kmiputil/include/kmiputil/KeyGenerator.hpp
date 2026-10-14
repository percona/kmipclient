/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_KEY_GENERATOR_HPP
#define KMIPUTIL_KEY_GENERATOR_HPP

#include "kmipclient/SymmetricKey.hpp"
#include "kmipclient/types.hpp"

namespace kmiputil {

  /** Generates key material locally, e.g. to register it with a KMIP server.
   */
  class KeyGenerator {
  public:
    KeyGenerator() = delete;

    /**
     * @brief Generates a random AES key using the OpenSSL CSPRNG.
     * @throws kmipcore::KmipException if OpenSSL cannot produce random bytes.
     */
    [[nodiscard]] static kmipclient::SymmetricKey generate_aes(
        kmipclient::aes_key_size key_size = kmipclient::aes_key_size::AES_256
    );
  };

}  // namespace kmiputil

#endif  // KMIPUTIL_KEY_GENERATOR_HPP
