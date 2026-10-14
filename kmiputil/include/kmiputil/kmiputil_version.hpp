/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_VERSION_HPP
#define KMIPUTIL_VERSION_HPP

/** @brief kmiputil semantic version major component. */
#define KMIPUTIL_VERSION_MAJOR 0
/** @brief kmiputil semantic version minor component. */
#define KMIPUTIL_VERSION_MINOR 1
/** @brief kmiputil semantic version patch component. */
#define KMIPUTIL_VERSION_PATCH 0

/** @brief Internal helper for macro stringification. */
#define KMIPUTIL_STRINGIFY_I(x) #x
/** @brief Internal helper for macro stringification. */
#define KMIPUTIL_TOSTRING_I(x) KMIPUTIL_STRINGIFY_I(x)

/** @brief Full kmiputil version string in "major.minor.patch" form. */
#define KMIPUTIL_VERSION_STR                                                   \
  KMIPUTIL_TOSTRING_I(KMIPUTIL_VERSION_MAJOR)                                  \
  "." KMIPUTIL_TOSTRING_I(KMIPUTIL_VERSION_MINOR) "." KMIPUTIL_TOSTRING_I(     \
      KMIPUTIL_VERSION_PATCH                                                   \
  )

#endif  // KMIPUTIL_VERSION_HPP
