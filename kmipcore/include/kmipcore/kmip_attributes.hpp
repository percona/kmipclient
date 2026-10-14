/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_KMIP_ATTRIBUTES_HPP
#define KMIPCORE_KMIP_ATTRIBUTES_HPP

#include "kmipcore/kmip_enums.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

namespace kmipcore {

  /**
   * @brief Type-safe KMIP attribute bag shared by Key, Secret, and other
   * managed objects.
   *
   * **Well-known typed attributes** — Cryptographic Algorithm, Cryptographic
   * Length, Cryptographic Usage Mask and the object lifecycle @ref state — are
   * stored with their native C++ types and accessed via dedicated typed
   * getters/setters.
   *
   * **All other attributes** — including user-defined / vendor attributes
   * allowed by the KMIP specification — are stored in a generic map keyed by
   * attribute name. Values preserve their native KMIP type through an @ref
   * AttributeValue variant (string, int32, int64, bool), so integer
   * user-defined attributes are not silently down-cast to strings.
   *
   * The @ref set(name, …) overloads automatically route calls for the four
   * well-known typed attributes to the appropriate typed setter, making it
   * straightforward to absorb raw server-response data without losing type
   * safety.
   *
   * Use @ref as_string_map() for a human-readable snapshot of all attributes
   * (typed fields serialised to strings, generic values converted via their
   * type).
   */
  class Attributes {
  public:
    /** Discriminated union for user-defined / generic attribute values. */
    using AttributeValue = std::variant<std::string, int32_t, int64_t, bool>;
    using GenericMap = std::unordered_map<std::string, AttributeValue>;
    /** Convenience alias for the plain string snapshot returned by @ref
     * as_string_map(). */
    using StringMap = std::unordered_map<std::string, std::string>;

    Attributes() = default;
    ~Attributes() = default;
    Attributes(const Attributes &) = default;
    Attributes &operator=(const Attributes &) = default;
    Attributes(Attributes &&) noexcept = default;
    Attributes &operator=(Attributes &&) noexcept = default;

    // -------------------------------------------------------------------------
    // Well-known typed getters
    // -------------------------------------------------------------------------

    /** @brief Returns Cryptographic Algorithm, or KMIP_CRYPTOALG_UNSET when
     * absent. */
    [[nodiscard]] cryptographic_algorithm algorithm() const noexcept;

    /** @brief Returns Cryptographic Length in bits, or std::nullopt when
     * absent. */
    [[nodiscard]] std::optional<int32_t> crypto_length() const noexcept;

    /** @brief Returns Cryptographic Usage Mask, or KMIP_CRYPTOMASK_UNSET when
     * absent. */
    [[nodiscard]] cryptographic_usage_mask usage_mask() const noexcept;

    /** @brief Returns the object lifecycle state, or KMIP_STATE_PRE_ACTIVE when
     * absent. */
    [[nodiscard]] state object_state() const noexcept;

    // -------------------------------------------------------------------------
    // Well-known typed setters — fluent, return *this
    // -------------------------------------------------------------------------

    /** @brief Sets Cryptographic Algorithm. Passing KMIP_CRYPTOALG_UNSET
     * clears. */
    Attributes &set_algorithm(cryptographic_algorithm alg) noexcept;
    /** @brief Sets Cryptographic Length in bits. */
    Attributes &set_crypto_length(int32_t len) noexcept;
    /** @brief Clears Cryptographic Length (marks it absent). */
    Attributes &clear_crypto_length() noexcept;
    /** @brief Sets Cryptographic Usage Mask. Passing KMIP_CRYPTOMASK_UNSET
     * clears. */
    Attributes &set_usage_mask(cryptographic_usage_mask mask) noexcept;
    /** @brief Sets the object lifecycle state. */
    Attributes &set_state(state st) noexcept;

    // -------------------------------------------------------------------------
    // Generic / user-defined attribute setters
    //
    // Well-known attribute names (Cryptographic Algorithm, Length, Mask, State)
    // are automatically routed to the corresponding typed setter regardless of
    // which overload is used.
    // -------------------------------------------------------------------------

    /** @brief Stores a string attribute (routes well-known names to typed
     * setters). */
    Attributes &set(std::string_view name, std::string value);
    /** @brief Overload so a string literal binds here instead of the bool
     * overload below. */
    Attributes &set(std::string_view name, const char *value) {
      return set(name, std::string(value));
    }
    /** @brief Stores an integer attribute (routes well-known names to typed
     * setters). */
    Attributes &set(std::string_view name, int32_t value) noexcept;
    /** @brief Stores a long-integer attribute. */
    Attributes &set(std::string_view name, int64_t value) noexcept;
    /** @brief Stores a boolean attribute. */
    Attributes &set(std::string_view name, bool value) noexcept;

    /** @brief Removes a generic attribute (no-op when absent). */
    void remove(std::string_view name) noexcept;

    // -------------------------------------------------------------------------
    // Generic attribute getters
    // -------------------------------------------------------------------------

    /**
     * @brief Returns true if the attribute is present — typed field or generic.
     */
    [[nodiscard]] bool has_attribute(std::string_view name) const noexcept;

    /**
     * @brief Returns the string value of a generic attribute, or empty string.
     *
     * Only returns a non-empty value when the stored variant holds a
     * @c std::string.  Use @ref get_int() or @ref get_long() for numeric attrs,
     * or @ref get_as_string() for a type-converting accessor.
     *
     * Does NOT look up the well-known typed fields (algorithm, length, etc.).
     * Use the dedicated typed getters for those.
     */
    [[nodiscard]] const std::string &get(std::string_view name) const noexcept;

    /**
     * @brief Returns a string representation of any generic attribute.
     *
     * Converts the stored variant to string (int → decimal, bool →
     * "true"/"false"). Returns @c std::nullopt when the attribute is absent.
     */
    [[nodiscard]] std::optional<std::string>
        get_as_string(std::string_view name) const;

    /** @brief Returns the int32 value of a generic attribute, or nullopt. */
    [[nodiscard]] std::optional<int32_t>
        get_int(std::string_view name) const noexcept;

    /** @brief Returns the int64 value of a generic attribute, or nullopt. */
    [[nodiscard]] std::optional<int64_t>
        get_long(std::string_view name) const noexcept;

    // -------------------------------------------------------------------------
    // Iteration / export
    // -------------------------------------------------------------------------

    /** @brief Direct read-only access to the typed generic attribute map. */
    [[nodiscard]] const GenericMap &generic() const noexcept;

    /**
     * @brief Returns all attributes as a plain string map.
     *
     * Well-known typed fields are serialised to their canonical string forms.
     * Generic @ref AttributeValue entries are converted (int → decimal,
     * bool → "true"/"false").  Suitable for display, logging, and
     * backward-compatible enumeration.
     */
    [[nodiscard]] StringMap as_string_map() const;

    /**
     * @brief Merges attributes from @p other into this object.
     *
     * Only fields explicitly set in @p other overwrite the corresponding field
     * in @p this.  Fields absent in @p other are left unchanged.
     */
    Attributes &merge(const Attributes &other);

  private:
    std::optional<cryptographic_algorithm> algo_;
    std::optional<int32_t> crypto_length_;
    std::optional<cryptographic_usage_mask> usage_mask_;
    std::optional<state> state_;
    GenericMap generic_;
  };

}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_ATTRIBUTES_HPP */
