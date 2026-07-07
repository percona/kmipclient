/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/Key.hpp"

#include "kmipcore/kmip_errors.hpp"

namespace kmipclient {

  Key::Key(std::span<const unsigned char> value, kmipcore::Attributes attrs)
    : key_value_(value.begin(), value.end()), attributes_(std::move(attrs)) {}

  kmipcore::Key Key::to_core_key() const {
    kmipcore::Key core_key(key_value_, type(), attributes_);
    core_key.set_key_format(key_format_);
    return core_key;
  }

  namespace {

    std::unique_ptr<Key> client_key_of_type(const kmipcore::Key &core_key) {
      switch (core_key.type()) {
        case KeyType::SYMMETRIC_KEY:
          return std::make_unique<SymmetricKey>(
              core_key.value(), core_key.attributes()
          );
        case KeyType::PUBLIC_KEY:
          return std::make_unique<PublicKey>(
              core_key.value(), core_key.attributes()
          );
        case KeyType::PRIVATE_KEY:
          return std::make_unique<PrivateKey>(
              core_key.value(), core_key.attributes()
          );
        case KeyType::CERTIFICATE:
          return std::make_unique<X509Certificate>(
              core_key.value(), core_key.attributes()
          );
        default:
          throw kmipcore::KmipException(
              "Unsupported key type in core->client conversion"
          );
      }
    }

  }  // namespace

  std::unique_ptr<Key> Key::from_core_key(const kmipcore::Key &core_key) {
    auto key = client_key_of_type(core_key);
    key->set_key_format(core_key.key_format());
    return key;
  }

}  // namespace kmipclient
