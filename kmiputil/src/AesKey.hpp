/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_AES_KEY_HPP
#define KMIPUTIL_AES_KEY_HPP

#include "kmipclient/SymmetricKey.hpp"

#include <span>

namespace kmiputil::detail {

  /** Wraps AES key material with the algorithm, length and usage-mask
   * attributes KMIP servers expect.
   * @throws kmipcore::KmipException unless the material is 128, 192 or 256
   * bits long. */
  kmipclient::SymmetricKey make_aes_key(std::span<const unsigned char> bytes);

}  // namespace kmiputil::detail

#endif  // KMIPUTIL_AES_KEY_HPP
