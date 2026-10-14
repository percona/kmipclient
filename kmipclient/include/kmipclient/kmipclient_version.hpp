/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_VERSION_H
#define KMIPCLIENT_VERSION_H

#include "kmipcore/kmipcore_version.hpp"

/** @brief kmipclient semantic version major component. */
#define KMIPCLIENT_VERSION_MAJOR 0
/** @brief kmipclient semantic version minor component. */
#define KMIPCLIENT_VERSION_MINOR 4
/** @brief kmipclient semantic version patch component. */
#define KMIPCLIENT_VERSION_PATCH 0

/** @brief Internal helper for macro-stringification. */
#define KMIPCLIENT_STRINGIFY_I(x) #x
/** @brief Internal helper for macro-stringification. */
#define KMIPCLIENT_TOSTRING_I(x) KMIPCLIENT_STRINGIFY_I(x)

/** @brief Full kmipclient version string in "major.minor.patch" form. */
#define KMIPCLIENT_VERSION_STR                                                 \
  KMIPCLIENT_TOSTRING_I(KMIPCLIENT_VERSION_MAJOR)                              \
  "." KMIPCLIENT_TOSTRING_I(                                                   \
      KMIPCLIENT_VERSION_MINOR                                                 \
  ) "." KMIPCLIENT_TOSTRING_I(KMIPCLIENT_VERSION_PATCH)

#endif  // KMIPCLIENT_VERSION_H
