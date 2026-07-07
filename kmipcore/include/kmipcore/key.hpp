/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_KEY_HPP
#define KMIPCORE_KEY_HPP

#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/managed_object.hpp"

#include <optional>

namespace kmipcore {

  /** @brief Key object families represented by @ref Key. */
  enum class KeyType { SYMMETRIC_KEY, PUBLIC_KEY, PRIVATE_KEY, CERTIFICATE };

  /**
   * Minimal crypto key representation as KMIP spec sees it.
   * Contains raw key bytes, key type, and a type-safe @ref Attributes bag.
   *
   * All attribute access goes through @ref attributes().
   * Use @ref attributes().algorithm(), @ref attributes().usage_mask(), etc.
   * for the well-known typed attributes, and @ref attributes().get() /
   * @ref attributes().generic() for user-defined / generic ones.
   */
  class Key : public ManagedObject {
  public:
    /**
     * @brief Constructs a KMIP key object.
     * @param value Raw key bytes.
     * @param k_type Key family.
     * @param attrs  Type-safe attribute bag.
     */
    explicit Key(
        std::span<const unsigned char> value,
        KeyType k_type,
        Attributes attrs = {}
    )
      : ManagedObject(value, std::move(attrs)), key_type(k_type) {}

    Key(const Key &) = default;
    Key &operator=(const Key &) = default;
    Key(Key &&) noexcept = default;
    Key &operator=(Key &&) noexcept = default;

    /** @brief Returns key family discriminator. */
    [[nodiscard]] KeyType type() const noexcept { return key_type; }

    /** @brief Returns key length in bytes. */
    [[nodiscard]] size_t size() const noexcept { return value_.size(); }

    /**
     * @brief Key Format Type of the value (KMIP 1.4 §9.1.3.2.3), e.g.
     * KMIP_KEYFORMAT_PKCS1 for a key a server returned that way, or nullopt
     * for the default of its type: Raw for symmetric keys, PKCS#8 for
     * private keys, X.509 for public keys.
     */
    [[nodiscard]] std::optional<int32_t> key_format() const noexcept {
      return key_format_;
    }
    /** @brief Sets the Key Format Type of the value. */
    void set_key_format(std::optional<int32_t> format) noexcept {
      key_format_ = format;
    }

  private:
    KeyType key_type;
    std::optional<int32_t> key_format_;
  };

}  // namespace kmipcore

#endif  // KMIPCORE_KEY_HPP
