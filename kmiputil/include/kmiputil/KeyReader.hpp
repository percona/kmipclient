/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_KEY_READER_HPP
#define KMIPUTIL_KEY_READER_HPP

#include "kmipclient/KeyBase.hpp"
#include "kmipclient/SymmetricKey.hpp"

#include <memory>
#include <span>
#include <string_view>

namespace kmiputil {

  /**
   * Builds client key objects from external representations (raw bytes, hex,
   * Base64, PEM). Kept out of the @ref kmipclient::Key hierarchy so the key
   * classes stay limited to the KMIP object model.
   */
  class KeyReader {
  public:
    KeyReader() = delete;

    /**
     * @brief Creates an AES key from a hexadecimal string.
     * @throws kmipcore::KmipException on invalid hex or a key length other
     * than 128, 192 or 256 bits.
     */
    [[nodiscard]] static kmipclient::SymmetricKey
        aes_from_hex(std::string_view hex);

    /**
     * @brief Creates an AES key from a Base64 string.
     * @throws kmipcore::KmipException on a key length other than 128, 192 or
     * 256 bits.
     */
    [[nodiscard]] static kmipclient::SymmetricKey
        aes_from_base64(std::string_view base64);

    /**
     * @brief Creates an AES key from raw key bytes.
     * @throws kmipcore::KmipException on a key length other than 128, 192 or
     * 256 bits.
     */
    [[nodiscard]] static kmipclient::SymmetricKey
        aes_from_value(std::span<const unsigned char> value);

    /**
     * @brief Parses PEM text into the matching client key type.
     *
     * Recognizes, in this order: an X.509 certificate, an unencrypted private
     * key, a public key, and finally Base64 key material between
     * SYMMETRIC KEY BEGIN/END lines, read as an AES key. Encrypted private
     * keys are not supported.
     * @throws kmipcore::KmipException if the PEM matches none of these.
     */
    [[nodiscard]] static std::unique_ptr<kmipclient::Key>
        from_PEM(std::string_view pem);
  };

}  // namespace kmiputil

#endif  // KMIPUTIL_KEY_READER_HPP
