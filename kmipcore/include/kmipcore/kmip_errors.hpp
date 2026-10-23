/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_KMIP_ERRORS_HPP
#define KMIPCORE_KMIP_ERRORS_HPP

#include "kmipcore/kmip_enums.hpp"

#include <string>
#include <system_error>

namespace kmipcore {

  /**
   * @brief Returns the KMIP-specific std::error_category.
   */
  [[nodiscard]] const std::error_category &kmip_category() noexcept;

  /**
   * @brief Creates an error_code in the KMIP category from a native code.
   */
  [[nodiscard]] std::error_code
      make_kmip_error_code(int native_error_code) noexcept;

  /**
   * @brief Base exception for KMIP core protocol/encoding failures.
   */
  class KmipException : public std::system_error {
  public:
    /** @brief Creates an exception with message only. */
    explicit KmipException(const std::string &msg);
    /** @brief Creates an exception with numeric status code and message. */
    KmipException(int native_error_code, const std::string &msg);
  };

  // ---------------------------------------------------------------------------
  // Checked conversions of attacker-controlled enumeration values.
  //
  // These validate a raw wire value against the known KMIP value tables and
  // throw KmipException on an out-of-range code, so the parsers never cast a
  // malicious value into a scoped enum that steers key-handling decisions.
  // ---------------------------------------------------------------------------

  [[nodiscard]] inline cryptographic_algorithm
      checked_cryptographic_algorithm(std::int32_t value) {
    if (!is_valid_cryptographic_algorithm(value)) {
      throw KmipException(
          KMIP_ENUM_UNSUPPORTED,
          "Unknown Cryptographic Algorithm enumeration value: " +
              std::to_string(value)
      );
    }
    return static_cast<cryptographic_algorithm>(value);
  }

  [[nodiscard]] inline state checked_state(std::int32_t value) {
    if (!is_valid_state(value)) {
      throw KmipException(
          KMIP_ENUM_UNSUPPORTED,
          "Unknown State enumeration value: " + std::to_string(value)
      );
    }
    return static_cast<state>(value);
  }

  [[nodiscard]] inline secret_data_type
      checked_secret_data_type(std::int32_t value) {
    if (!is_valid_secret_data_type(value)) {
      throw KmipException(
          KMIP_ENUM_UNSUPPORTED,
          "Unknown Secret Data Type enumeration value: " + std::to_string(value)
      );
    }
    return static_cast<secret_data_type>(value);
  }

  /** @deprecated Every Cryptographic Usage Mask is valid; this only casts. */
  [[deprecated("every Cryptographic Usage Mask value is valid; cast instead")]]
  [[nodiscard]] inline cryptographic_usage_mask
      checked_cryptographic_usage_mask(std::int32_t value) {
    return static_cast<cryptographic_usage_mask>(value);
  }

}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_ERRORS_HPP */
