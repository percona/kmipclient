/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_KEY_PARSER_HPP
#define KMIPCORE_KEY_PARSER_HPP

#include "kmipcore/key.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_responses.hpp"
#include "kmipcore/secret.hpp"

#include <memory>
#include <optional>
#include <span>

namespace kmipcore {

  /**
   * @brief Decodes KMIP Get payloads into Key or Secret model objects.
   */
  class KeyParser {
  public:
    /** @brief Default constructor. */
    KeyParser() = default;
    /**
     * @brief Parses typed Get response item into a key object.
     * @param item Typed Get response batch item.
     */
    static Key parseGetKeyResponse(const GetResponseBatchItem &item);
    /**
     * @brief Parses typed Get response item into a secret object.
     * @param item Typed Get response batch item.
     */
    static Secret parseGetSecretResponse(const GetResponseBatchItem &item);
    /**
     * @brief Returns the Key Format Type of the key in a Get response, or
     * nullopt when the object has no Key Block.
     * @param item Typed Get response batch item.
     */
    static std::optional<int32_t>
        keyFormatType(const GetResponseBatchItem &item);

    /**
     * @brief Checks symmetric key material against its attributes; throws
     *        KmipException when they disagree.
     *
     * The material must not be empty, and Raw material must be as long as a
     * stated Cryptographic Length, which is "the length in bits of the
     * clear-text cryptographic key material" (KMIP 1.4 §3.5, 2.0 §4.15).
     * DES and 3DES material may also carry one parity bit per byte (1.4
     * §2.1.3, 2.0 §3.1), so 8/7 of the length is accepted for them too.
     * parseGetKeyResponse() runs it against the Key Block; callers that add
     * attributes from elsewhere (Get Attributes) can run it again.
     */
    static void checkSymmetricKeyMaterial(
        std::span<const unsigned char> material,
        int32_t key_format,
        const Attributes &attributes
    );

  private:
    /** @brief Internal key parser used by typed public entry points. */
    static Key parseResponse(const std::shared_ptr<Element> &payload);
  };

}  // namespace kmipcore

#endif  // KMIPCORE_KEY_PARSER_HPP
