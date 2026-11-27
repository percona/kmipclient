/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_KMIP_BASICS_HPP
#define KMIPCORE_KMIP_BASICS_HPP

#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/secure_memory.hpp"

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace kmipcore {

  // Forward declaration for SerializationBuffer
  class SerializationBuffer;

  /** @brief Alias of KMIP tag enumeration type used by TTLV elements. */
  using Tag = tag;
  /** @brief Alias of KMIP type enumeration used by TTLV elements. */
  using Type = type;
  /** @brief KMIP Result Status numeric code type. */
  using KmipResultStatusCode = int32_t;
  /** @brief KMIP Result Reason numeric code type. */
  using KmipResultReasonCode = int32_t;

  struct Element;  // Forward declaration

  /** @brief TTLV Integer wrapper. */
  struct Integer {
    int32_t value;
  };
  /** @brief TTLV Long Integer wrapper. */
  struct LongInteger {
    int64_t value;
  };
  // The string-like wrappers below hold their bytes in zeroed-on-free
  // storage: keys, secret data and passwords travel through them on the way
  // to and from the wire, and any plain copy here would outlive the request.

  /** @brief TTLV Big Integer wrapper. */
  struct BigInteger {
    secure_bytes value;
  };
  /** @brief TTLV Enumeration wrapper. */
  struct Enumeration {
    int32_t value;
  };
  /** @brief TTLV Boolean wrapper. */
  struct Boolean {
    bool value;
  };  // usually uint64_t 0/1 in TTLV, but bool is fine in abstract
      // representation
  /** @brief TTLV Text String wrapper. */
  struct TextString {
    secure_string value;
  };
  /** @brief TTLV Byte String wrapper. */
  struct ByteString {
    secure_bytes value;
  };
  /** @brief TTLV Date-Time wrapper (POSIX time). */
  struct DateTime {
    int64_t value;
  };  // 64-bit signed integer POSIX time
  /**
   * @brief TTLV Date-Time Extended wrapper (KMIP 2.0, microsecond precision).
   *
   * Encoded as a signed 64-bit big-endian integer representing microseconds
   * since the Unix epoch (midnight, January 1, 1970 UTC).  Wire format is
   * identical to DateTime; the two are distinguished by type code 0x09 vs 0x0B.
   */
  struct DateTimeExtended {
    int64_t value;
  };  // 64-bit signed integer, microseconds since Unix epoch
  /** @brief TTLV Interval wrapper (seconds). */
  struct Interval {
    uint32_t value;
  };  // 32-bit unsigned integer

  /**
   * @brief TTLV Structure wrapper containing nested elements.
   */
  struct Structure {
    std::vector<std::shared_ptr<Element>> items;

    /** @brief Appends a child element to the structure. */
    void add(const std::shared_ptr<Element> &element) {
      items.push_back(element);
    }

    /** @brief Finds the first child with the specified tag. */
    [[nodiscard]] std::shared_ptr<Element> find(Tag child_tag) const;
    /** @brief Finds all children with the specified tag. */
    [[nodiscard]] std::vector<std::shared_ptr<Element>>
        findAll(Tag child_tag) const;
  };

  /** @brief Variant that represents any supported KMIP TTLV value type. */
  using Value = std::variant<
      Structure,
      Integer,
      LongInteger,
      BigInteger,
      Enumeration,
      Boolean,
      TextString,
      ByteString,
      DateTime,
      DateTimeExtended,
      Interval>;

  /**
   * @brief Generic TTLV node containing tag, type, and typed value.
   */
  struct Element {
    /** KMIP tag describing semantic meaning of this node. */
    Tag tag = tag::KMIP_TAG_DEFAULT;
    /** KMIP TTLV type code for @ref value. */
    Type type = static_cast<Type>(KMIP_TYPE_STRUCTURE);
    /** Typed payload value of this node. */
    Value value = Structure{};

    /**
     * @brief Constructs a TTLV element with explicit fields.
     */
    Element(Tag t, Type tp, Value v) : tag(t), type(tp), value(std::move(v)) {}
    /** @brief Default-constructs an empty element. */
    Element() = default;

    /** @brief Creates a Structure element. */
    static std::shared_ptr<Element> createStructure(Tag t);
    /** @brief Creates an Integer element. */
    static std::shared_ptr<Element> createInteger(Tag t, int32_t v);
    /** @brief Creates a Long Integer element. */
    static std::shared_ptr<Element> createLongInteger(Tag t, int64_t v);
    /** @brief Creates a Big Integer element. */
    static std::shared_ptr<Element>
        createBigInteger(Tag t, std::span<const uint8_t> v);
    /** @brief Creates a Big Integer element from a list of bytes. */
    static std::shared_ptr<Element>
        createBigInteger(Tag t, std::initializer_list<uint8_t> v);
    /** @brief Creates an Enumeration element. */
    static std::shared_ptr<Element> createEnumeration(Tag t, int32_t v);
    /** @brief Creates a Boolean element. */
    static std::shared_ptr<Element> createBoolean(Tag t, bool v);
    /** @brief Creates a Text String element. */
    static std::shared_ptr<Element> createTextString(Tag t, std::string_view v);
    /** @brief Creates a Byte String element. */
    static std::shared_ptr<Element>
        createByteString(Tag t, std::span<const uint8_t> v);
    /** @brief Creates a Byte String element from a list of bytes. */
    static std::shared_ptr<Element>
        createByteString(Tag t, std::initializer_list<uint8_t> v);
    /** @brief Creates a Date-Time element (seconds since Unix epoch). */
    static std::shared_ptr<Element> createDateTime(Tag t, int64_t v);
    /** @brief Creates a Date-Time Extended element (KMIP 2.0, microseconds
     * since Unix epoch). */
    static std::shared_ptr<Element> createDateTimeExtended(Tag t, int64_t v);
    /** @brief Creates an Interval element. */
    static std::shared_ptr<Element> createInterval(Tag t, uint32_t v);

    /**
     * @brief Serializes this node into the provided TTLV buffer.
     * @param buf Destination serialization buffer.
     */
    void serialize(SerializationBuffer &buf) const;

    /**
     * @brief Deserializes one element from raw TTLV data.
     * @param data Input TTLV byte span.
     * @param offset Current read offset; advanced past parsed element.
     * @return Parsed element tree rooted at this node.
     */
    static std::shared_ptr<Element>
        deserialize(std::span<const uint8_t> data, size_t &offset);

    /** @brief Returns mutable structure view when this node is a structure. */
    [[nodiscard]] Structure *asStructure();
    /** @brief Returns const structure view when this node is a structure. */
    [[nodiscard]] const Structure *asStructure() const;

    /** @brief Returns first direct child with the given tag, if present. */
    [[nodiscard]] std::shared_ptr<Element> getChild(Tag child_tag) const;
    /** @brief Returns all direct children with the given tag. */
    [[nodiscard]] std::vector<std::shared_ptr<Element>>
        getChildren(Tag child_tag) const;

    /** @brief Converts value to Integer representation. */
    [[nodiscard]] int32_t toInt() const;
    /** @brief Converts value to Long Integer representation. */
    [[nodiscard]] int64_t toLong() const;
    /** @brief Converts value to Boolean representation. */
    [[nodiscard]] bool toBool() const;
    /** @brief Converts value to Text String representation. */
    [[nodiscard]] std::string toString() const;
    /** @brief Converts value to Byte String representation. */
    [[nodiscard]] std::vector<uint8_t> toBytes() const;
    /**
     * @brief Returns a view of a Text String value without copying it.
     *
     * The view is valid while this element is alive and unchanged.
     */
    [[nodiscard]] std::string_view stringView() const;
    /**
     * @brief Returns a view of a Byte String or Big Integer value without
     *        copying it.
     *
     * The view is valid while this element is alive and unchanged.
     */
    [[nodiscard]] std::span<const uint8_t> bytesView() const;
    /** @brief Converts value to Enumeration representation. */
    [[nodiscard]] int32_t toEnum() const;
    /** @brief Converts value to Interval representation. */
    [[nodiscard]] uint32_t toInterval() const;
  };

}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_BASICS_HPP */
