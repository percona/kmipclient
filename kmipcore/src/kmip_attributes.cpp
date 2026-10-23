/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/kmip_attributes.hpp"

#include "kmipcore/kmip_attribute_names.hpp"
#include "kmipcore/kmip_formatter.hpp"

#include <cerrno>
#include <cstdlib>
#include <string_view>

namespace kmipcore {

  namespace {

    // Parses a decimal enumeration value, 0..0xFFFFFFFF, so the numeric form
    // of an unnamed value (e.g. an Extensions code, 8XXXXXXX) reads back.
    [[nodiscard]] std::optional<std::uint32_t>
        parse_enum_number(std::string_view s) {
      if (s.empty() || s.find_first_not_of("0123456789") != s.npos) {
        return std::nullopt;
      }
      const std::string str(s);
      errno = 0;
      const unsigned long long v = std::strtoull(str.c_str(), nullptr, 10);
      if (errno != 0 || v > 0xFFFFFFFFull) {
        return std::nullopt;
      }
      return static_cast<std::uint32_t>(v);
    }

    // ---- Algorithm string conversion ----------------------------------------

    [[nodiscard]] std::string algorithm_to_string(cryptographic_algorithm alg) {
      using A = cryptographic_algorithm;
      switch (alg) {
        case A::KMIP_CRYPTOALG_DES:
          return "DES";
        case A::KMIP_CRYPTOALG_TRIPLE_DES:
          return "3DES";
        case A::KMIP_CRYPTOALG_AES:
          return "AES";
        case A::KMIP_CRYPTOALG_RSA:
          return "RSA";
        case A::KMIP_CRYPTOALG_DSA:
          return "DSA";
        case A::KMIP_CRYPTOALG_ECDSA:
          return "ECDSA";
        case A::KMIP_CRYPTOALG_HMAC_SHA1:
          return "HMAC-SHA1";
        case A::KMIP_CRYPTOALG_HMAC_SHA224:
          return "HMAC-SHA224";
        case A::KMIP_CRYPTOALG_HMAC_SHA256:
          return "HMAC-SHA256";
        case A::KMIP_CRYPTOALG_HMAC_SHA384:
          return "HMAC-SHA384";
        case A::KMIP_CRYPTOALG_HMAC_SHA512:
          return "HMAC-SHA512";
        case A::KMIP_CRYPTOALG_HMAC_MD5:
          return "HMAC-MD5";
        case A::KMIP_CRYPTOALG_DH:
          return "DH";
        case A::KMIP_CRYPTOALG_ECDH:
          return "ECDH";
        default:
          return std::to_string(static_cast<std::uint32_t>(alg));
      }
    }

    [[nodiscard]] std::optional<cryptographic_algorithm>
        parse_algorithm_string(std::string_view s) {
      using A = cryptographic_algorithm;
      if (s == "AES") {
        return A::KMIP_CRYPTOALG_AES;
      }
      if (s == "RSA") {
        return A::KMIP_CRYPTOALG_RSA;
      }
      if (s == "DSA") {
        return A::KMIP_CRYPTOALG_DSA;
      }
      if (s == "ECDSA") {
        return A::KMIP_CRYPTOALG_ECDSA;
      }
      if (s == "DES") {
        return A::KMIP_CRYPTOALG_DES;
      }
      if (s == "3DES") {
        return A::KMIP_CRYPTOALG_TRIPLE_DES;
      }
      if (s == "DH") {
        return A::KMIP_CRYPTOALG_DH;
      }
      if (s == "ECDH") {
        return A::KMIP_CRYPTOALG_ECDH;
      }
      if (s == "HMAC-SHA1") {
        return A::KMIP_CRYPTOALG_HMAC_SHA1;
      }
      if (s == "HMAC-SHA224") {
        return A::KMIP_CRYPTOALG_HMAC_SHA224;
      }
      if (s == "HMAC-SHA256") {
        return A::KMIP_CRYPTOALG_HMAC_SHA256;
      }
      if (s == "HMAC-SHA384") {
        return A::KMIP_CRYPTOALG_HMAC_SHA384;
      }
      if (s == "HMAC-SHA512") {
        return A::KMIP_CRYPTOALG_HMAC_SHA512;
      }
      if (s == "HMAC-MD5") {
        return A::KMIP_CRYPTOALG_HMAC_MD5;
      }
      // Try raw numeric
      if (const auto v = parse_enum_number(s)) {
        return static_cast<A>(*v);
      }
      return std::nullopt;
    }

    [[nodiscard]] std::optional<state> parse_state_string(std::string_view s) {
      constexpr std::string_view prefix = "KMIP_STATE_";
      if (s.starts_with(prefix)) {
        s.remove_prefix(prefix.size());
      }
      if (s == "PRE_ACTIVE") {
        return state::KMIP_STATE_PRE_ACTIVE;
      }
      if (s == "ACTIVE") {
        return state::KMIP_STATE_ACTIVE;
      }
      if (s == "DEACTIVATED") {
        return state::KMIP_STATE_DEACTIVATED;
      }
      if (s == "COMPROMISED") {
        return state::KMIP_STATE_COMPROMISED;
      }
      if (s == "DESTROYED") {
        return state::KMIP_STATE_DESTROYED;
      }
      if (s == "DESTROYED_COMPROMISED") {
        return state::KMIP_STATE_DESTROYED_COMPROMISED;
      }
      if (const auto v = parse_enum_number(s)) {
        return static_cast<state>(*v);
      }
      return std::nullopt;
    }

    // A defined State by name, any other (e.g. an Extensions value) by
    // number, which parse_state_string() reads back.
    [[nodiscard]] std::string state_to_attribute_string(state st) {
      const auto raw = static_cast<std::uint32_t>(st);
      if (raw >= static_cast<std::uint32_t>(state::KMIP_STATE_PRE_ACTIVE) &&
          raw <= static_cast<std::uint32_t>(
                     state::KMIP_STATE_DESTROYED_COMPROMISED
                 )) {
        return state_to_string(st);
      }
      return std::to_string(raw);
    }

    // ---- AttributeValue → string --------------------------------------------

    [[nodiscard]] std::string
        value_to_string(const Attributes::AttributeValue &v) {
      return std::visit(
          [](const auto &val) -> std::string {
            using T = std::decay_t<decltype(val)>;
            if constexpr (std::is_same_v<T, std::string>) {
              return val;
            } else if constexpr (std::is_same_v<T, bool>) {
              return val ? "true" : "false";
            } else {
              return std::to_string(val);
            }
          },
          v
      );
    }

  }  // namespace

  // ---------------------------------------------------------------------------
  // Typed getters
  // ---------------------------------------------------------------------------

  cryptographic_algorithm Attributes::algorithm() const noexcept {
    return algo_.value_or(cryptographic_algorithm::KMIP_CRYPTOALG_UNSET);
  }
  std::optional<int32_t> Attributes::crypto_length() const noexcept {
    return crypto_length_;
  }
  cryptographic_usage_mask Attributes::usage_mask() const noexcept {
    return usage_mask_.value_or(
        cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET
    );
  }
  state Attributes::object_state() const noexcept {
    return state_.value_or(state::KMIP_STATE_PRE_ACTIVE);
  }

  // ---------------------------------------------------------------------------
  // Typed setters
  // ---------------------------------------------------------------------------

  Attributes &Attributes::set_algorithm(cryptographic_algorithm alg) noexcept {
    if (alg == cryptographic_algorithm::KMIP_CRYPTOALG_UNSET) {
      algo_.reset();
    } else {
      algo_ = alg;
    }
    return *this;
  }
  Attributes &Attributes::set_crypto_length(int32_t len) noexcept {
    crypto_length_ = len;
    return *this;
  }
  Attributes &Attributes::clear_crypto_length() noexcept {
    crypto_length_.reset();
    return *this;
  }
  Attributes &
      Attributes::set_usage_mask(cryptographic_usage_mask mask) noexcept {
    if (mask == cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET) {
      usage_mask_.reset();
    } else {
      usage_mask_ = mask;
    }
    return *this;
  }
  Attributes &Attributes::set_state(state st) noexcept {
    state_ = st;
    return *this;
  }

  // ---------------------------------------------------------------------------
  // Generic setters — with routing for well-known names
  // ---------------------------------------------------------------------------

  Attributes &Attributes::set(std::string_view name, std::string value) {
    if (name == KMIP_ATTR_NAME_CRYPTO_ALG) {
      if (const auto parsed = parse_algorithm_string(value); parsed) {
        algo_ = *parsed;
      }
      return *this;
    }
    if (name == KMIP_ATTR_NAME_CRYPTO_LEN) {
      const std::string s(value);
      char *end = nullptr;
      errno = 0;
      const long v = std::strtol(s.c_str(), &end, 10);
      if (errno == 0 && end != s.c_str() && *end == '\0') {
        crypto_length_ = static_cast<int32_t>(v);
      }
      return *this;
    }
    if (name == KMIP_ATTR_NAME_CRYPTO_USAGE_MASK) {
      const std::string s(value);
      char *end = nullptr;
      errno = 0;
      const long v = std::strtol(s.c_str(), &end, 10);
      if (errno == 0 && end != s.c_str() && *end == '\0') {
        const auto mask = static_cast<cryptographic_usage_mask>(v);
        if (mask != cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET) {
          usage_mask_ = mask;
        }
      }
      return *this;
    }
    if (name == KMIP_ATTR_NAME_STATE) {
      if (const auto parsed = parse_state_string(value); parsed) {
        state_ = *parsed;
      }
      return *this;
    }
    generic_[std::string(name)] = std::move(value);
    return *this;
  }

  Attributes &Attributes::set(std::string_view name, int32_t value) noexcept {
    if (name == KMIP_ATTR_NAME_CRYPTO_LEN) {
      crypto_length_ = value;
      return *this;
    }
    if (name == KMIP_ATTR_NAME_CRYPTO_USAGE_MASK) {
      const auto mask = static_cast<cryptographic_usage_mask>(value);
      if (mask != cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET) {
        usage_mask_ = mask;
      }
      return *this;
    }
    if (name == KMIP_ATTR_NAME_CRYPTO_ALG) {
      const auto alg = static_cast<cryptographic_algorithm>(value);
      if (alg != cryptographic_algorithm::KMIP_CRYPTOALG_UNSET) {
        algo_ = alg;
      }
      return *this;
    }
    if (name == KMIP_ATTR_NAME_STATE) {
      state_ = static_cast<state>(value);
      return *this;
    }
    generic_[std::string(name)] = value;
    return *this;
  }

  Attributes &Attributes::set(std::string_view name, int64_t value) noexcept {
    generic_[std::string(name)] = value;
    return *this;
  }

  Attributes &Attributes::set(std::string_view name, bool value) noexcept {
    generic_[std::string(name)] = value;
    return *this;
  }

  void Attributes::remove(std::string_view name) noexcept {
    generic_.erase(std::string(name));
  }

  // ---------------------------------------------------------------------------
  // Generic getters
  // ---------------------------------------------------------------------------

  bool Attributes::has_attribute(std::string_view name) const noexcept {
    if (name == KMIP_ATTR_NAME_CRYPTO_ALG) {
      return algo_.has_value();
    }
    if (name == KMIP_ATTR_NAME_CRYPTO_LEN) {
      return crypto_length_.has_value();
    }
    if (name == KMIP_ATTR_NAME_CRYPTO_USAGE_MASK) {
      return usage_mask_.has_value();
    }
    if (name == KMIP_ATTR_NAME_STATE) {
      return state_.has_value();
    }
    return generic_.count(std::string(name)) > 0;
  }

  const std::string &Attributes::get(std::string_view name) const noexcept {
    static const std::string empty;
    const auto it = generic_.find(std::string(name));
    if (it == generic_.end()) {
      return empty;
    }
    if (const auto *s = std::get_if<std::string>(&it->second)) {
      return *s;
    }
    return empty;
  }

  std::optional<std::string>
      Attributes::get_as_string(std::string_view name) const {
    const auto it = generic_.find(std::string(name));
    if (it == generic_.end()) {
      return std::nullopt;
    }
    return value_to_string(it->second);
  }

  std::optional<int32_t>
      Attributes::get_int(std::string_view name) const noexcept {
    const auto it = generic_.find(std::string(name));
    if (it == generic_.end()) {
      return std::nullopt;
    }
    if (const auto *i = std::get_if<int32_t>(&it->second)) {
      return *i;
    }
    return std::nullopt;
  }

  std::optional<int64_t>
      Attributes::get_long(std::string_view name) const noexcept {
    const auto it = generic_.find(std::string(name));
    if (it == generic_.end()) {
      return std::nullopt;
    }
    if (const auto *l = std::get_if<int64_t>(&it->second)) {
      return *l;
    }
    return std::nullopt;
  }

  const Attributes::GenericMap &Attributes::generic() const noexcept {
    return generic_;
  }

  // ---------------------------------------------------------------------------
  // Iteration / export
  // ---------------------------------------------------------------------------

  Attributes::StringMap Attributes::as_string_map() const {
    StringMap result;
    for (const auto &[key, val] : generic_) {
      result[key] = value_to_string(val);
    }
    if (algo_.has_value()) {
      result[std::string(KMIP_ATTR_NAME_CRYPTO_ALG)] =
          algorithm_to_string(*algo_);
    }
    if (crypto_length_.has_value()) {
      result[std::string(KMIP_ATTR_NAME_CRYPTO_LEN)] =
          std::to_string(*crypto_length_);
    }
    if (usage_mask_.has_value()) {
      result[std::string(KMIP_ATTR_NAME_CRYPTO_USAGE_MASK)] =
          usage_mask_to_string(static_cast<std::uint32_t>(*usage_mask_));
    }
    if (state_.has_value()) {
      result[std::string(KMIP_ATTR_NAME_STATE)] =
          state_to_attribute_string(*state_);
    }
    return result;
  }

  Attributes &Attributes::merge(const Attributes &other) {
    if (other.algo_.has_value()) {
      algo_ = other.algo_;
    }
    if (other.crypto_length_.has_value()) {
      crypto_length_ = other.crypto_length_;
    }
    if (other.usage_mask_.has_value()) {
      usage_mask_ = other.usage_mask_;
    }
    if (other.state_.has_value()) {
      state_ = other.state_;
    }
    for (const auto &[k, v] : other.generic_) {
      generic_[k] = v;
    }
    return *this;
  }

}  // namespace kmipcore
