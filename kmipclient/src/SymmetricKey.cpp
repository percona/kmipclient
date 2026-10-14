/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/SymmetricKey.hpp"

namespace kmipclient {

  std::unique_ptr<Key> SymmetricKey::clone() const {
    return std::make_unique<SymmetricKey>(*this);
  }

}  // namespace kmipclient
