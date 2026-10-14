/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_SYMMETRIC_KEY_HPP
#define KMIPCLIENT_SYMMETRIC_KEY_HPP

#include "kmipclient/KeyBase.hpp"

namespace kmipclient {

  /**
   * Symmetric key. To build one from hex, Base64 or raw bytes, or to generate
   * one, use kmiputil::KeyReader and kmiputil::KeyGenerator.
   */
  class SymmetricKey final : public Key {
  public:
    using Key::Key;

    [[nodiscard]] KeyType type() const noexcept override {
      return KeyType::SYMMETRIC_KEY;
    }
    [[nodiscard]] std::unique_ptr<Key> clone() const override;
  };

}  // namespace kmipclient

#endif  // KMIPCLIENT_SYMMETRIC_KEY_HPP
