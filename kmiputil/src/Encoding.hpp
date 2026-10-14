/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_ENCODING_HPP
#define KMIPUTIL_ENCODING_HPP

#include "kmipcore/secure_memory.hpp"

#include <span>
#include <string_view>

namespace kmiputil::encoding {

  /** @throws kmipcore::KmipException on empty input, odd length or a non-hex
   * character. */
  kmipcore::secure_bytes from_hex(std::string_view hex);
  /** Lowercase hex. */
  kmipcore::secure_string to_hex(std::span<const unsigned char> bytes);

  /** Lenient: skips characters outside the Base64 alphabet and stops at the
   * first '='. */
  kmipcore::secure_bytes from_base64(std::string_view base64);
  /** Padded Base64, no line breaks. */
  kmipcore::secure_string to_base64(std::span<const unsigned char> bytes);

}  // namespace kmiputil::encoding

#endif  // KMIPUTIL_ENCODING_HPP
