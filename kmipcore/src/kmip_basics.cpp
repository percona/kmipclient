/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/kmip_basics.hpp"

#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <bit>
#include <cstring>
#include <iomanip>
#include <vector>

namespace kmipcore {

  // Helper functions for big-endian: return a value whose in-memory byte
  // order is big-endian, so it can be written to the wire with memcpy.
  static std::uint32_t to_be32(std::uint32_t v) {
    if constexpr (std::endian::native == std::endian::big) {
      return v;
    }
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
  }
  static std::uint64_t to_be64(std::uint64_t v) {
    if constexpr (std::endian::native == std::endian::big) {
      return v;
    }
    return (static_cast<std::uint64_t>(to_be32(static_cast<std::uint32_t>(v)))
            << 32) |
           to_be32(static_cast<std::uint32_t>(v >> 32));
  }
  // Safe big-endian decoders from raw byte spans.
  static std::uint32_t
      read_be_u32(std::span<const std::uint8_t> data, std::size_t off) {
    return (static_cast<std::uint32_t>(data[off]) << 24) |
           (static_cast<std::uint32_t>(data[off + 1]) << 16) |
           (static_cast<std::uint32_t>(data[off + 2]) << 8) |
           static_cast<std::uint32_t>(data[off + 3]);
  }

  static std::uint64_t
      read_be_u64(std::span<const std::uint8_t> data, std::size_t off) {
    return (static_cast<std::uint64_t>(data[off]) << 56) |
           (static_cast<std::uint64_t>(data[off + 1]) << 48) |
           (static_cast<std::uint64_t>(data[off + 2]) << 40) |
           (static_cast<std::uint64_t>(data[off + 3]) << 32) |
           (static_cast<std::uint64_t>(data[off + 4]) << 24) |
           (static_cast<std::uint64_t>(data[off + 5]) << 16) |
           (static_cast<std::uint64_t>(data[off + 6]) << 8) |
           static_cast<std::uint64_t>(data[off + 7]);
  }

  static void validate_zero_padding(
      std::span<const std::uint8_t> data,
      std::size_t value_offset,
      std::size_t value_length,
      std::size_t padded_length
  ) {
    for (std::size_t i = value_offset + value_length;
         i < value_offset + padded_length;
         ++i) {
      if (data[i] != 0) {
        throw KmipException(
            "Invalid TTLV padding: non-zero padding byte found"
        );
      }
    }
  }

  void Element::serialize(SerializationBuffer &buf) const {
    // Write Tag (3 bytes, big-endian)
    const auto raw_tag = static_cast<std::uint32_t>(tag);
    buf.writeByte((raw_tag >> 16) & 0xFF);
    buf.writeByte((raw_tag >> 8) & 0xFF);
    buf.writeByte(raw_tag & 0xFF);

    // Write Type (1 byte)
    buf.writeByte(static_cast<std::uint8_t>(type));

    // First pass: calculate content and payload length
    SerializationBuffer content_buf;
    std::uint32_t payload_length = 0;

    if (std::holds_alternative<Structure>(value)) {
      const auto &s = std::get<Structure>(value);
      for (const auto &item : s.items) {
        item->serialize(content_buf);  // Recursive call
      }
      payload_length = content_buf.size();
    } else if (std::holds_alternative<Integer>(value)) {
      std::uint32_t wire =
          to_be32(static_cast<std::uint32_t>(std::get<Integer>(value).value));
      content_buf.writeBytes(std::as_bytes(std::span{&wire, 1}));
      payload_length = 4;
    } else if (std::holds_alternative<LongInteger>(value)) {
      std::uint64_t wire = to_be64(
          static_cast<std::uint64_t>(std::get<LongInteger>(value).value)
      );
      content_buf.writeBytes(std::as_bytes(std::span{&wire, 1}));
      payload_length = 8;
    } else if (std::holds_alternative<BigInteger>(value)) {
      const auto &v = std::get<BigInteger>(value).value;
      content_buf.writeBytes(std::as_bytes(std::span(v.data(), v.size())));
      payload_length = v.size();
    } else if (std::holds_alternative<Enumeration>(value)) {
      std::uint32_t wire = to_be32(
          static_cast<std::uint32_t>(std::get<Enumeration>(value).value)
      );
      content_buf.writeBytes(std::as_bytes(std::span{&wire, 1}));
      payload_length = 4;
    } else if (std::holds_alternative<Boolean>(value)) {
      std::uint64_t v = std::get<Boolean>(value).value ? 1 : 0;
      v = to_be64(v);
      content_buf.writeBytes(std::as_bytes(std::span{&v, 1}));
      payload_length = 8;
    } else if (std::holds_alternative<TextString>(value)) {
      const auto &v = std::get<TextString>(value).value;
      content_buf.writePadded(std::as_bytes(std::span(v.data(), v.size())));
      payload_length = v.size();
    } else if (std::holds_alternative<ByteString>(value)) {
      const auto &v = std::get<ByteString>(value).value;
      content_buf.writePadded(std::as_bytes(std::span(v.data(), v.size())));
      payload_length = v.size();
    } else if (std::holds_alternative<DateTime>(value)) {
      std::uint64_t wire =
          to_be64(static_cast<std::uint64_t>(std::get<DateTime>(value).value));
      content_buf.writeBytes(std::as_bytes(std::span{&wire, 1}));
      payload_length = 8;
    } else if (std::holds_alternative<DateTimeExtended>(value)) {
      // KMIP 2.0: microseconds since Unix epoch; same 8-byte big-endian wire
      // format as DateTime, distinguished only by type code 0x0B.
      std::uint64_t wire = to_be64(
          static_cast<std::uint64_t>(std::get<DateTimeExtended>(value).value)
      );
      content_buf.writeBytes(std::as_bytes(std::span{&wire, 1}));
      payload_length = 8;
    } else if (std::holds_alternative<Interval>(value)) {
      std::uint32_t v = std::get<Interval>(value).value;
      v = to_be32(v);
      content_buf.writeBytes(std::as_bytes(std::span{&v, 1}));
      payload_length = 4;
    }

    // Write Length (4 bytes, big-endian)
    buf.writeByte((payload_length >> 24) & 0xFF);
    buf.writeByte((payload_length >> 16) & 0xFF);
    buf.writeByte((payload_length >> 8) & 0xFF);
    buf.writeByte(payload_length & 0xFF);

    // Write content (already padded from content_buf)
    if (content_buf.size() > 0) {
      buf.writeBytes(std::as_bytes(content_buf.span()));
    }

    // Add padding to align to 8 bytes
    std::size_t total_so_far =
        3 + 1 + 4 + content_buf.size();  // tag + type + length + content
    std::size_t padding = (8 - (total_so_far % 8)) % 8;
    for (std::size_t i = 0; i < padding; ++i) {
      buf.writeByte(0);
    }
  }

  static std::shared_ptr<Element> deserialize_impl(
      std::span<const std::uint8_t> data, std::size_t &offset, unsigned depth
  ) {
    if (depth > KMIP_MAX_STRUCTURE_DEPTH) {
      throw KmipException("TTLV structure nesting depth exceeds limit");
    }

    if (offset + 8 > data.size()) {
      throw KmipException("Buffer too short for header");
    }

    // Read Tag (3 bytes)
    std::uint32_t tag = (static_cast<std::uint32_t>(data[offset]) << 16) |
                        (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
                        static_cast<std::uint32_t>(data[offset + 2]);

    // Read Type (1 byte)
    Type type = static_cast<Type>(data[offset + 3]);

    // Read Length (4 bytes)
    std::uint32_t length = read_be_u32(data, offset + 4);

    offset += 8;

    // Check bounds
    // For Structure, length is the length of contents.
    // For Primitives, length is the unpadded length.
    // We need to calculate padded length to skip correctly.
    std::size_t padded_length = length;
    if (length % 8 != 0 && type != Type::KMIP_TYPE_STRUCTURE) {
      padded_length +=
          (8 -
           (length % 8));  // Doesn't apply to structure?
                           // Structure variable length is usually handled
                           // differently because it contains other items
                           // aligned on 8-byte boundaries. Actually for
                           // Structure type, length is sum of encoded items.
      // Since all encoded items are multiple of 8 bytes, Structure length
      // should be multiple of 8.
    }

    if (type == Type::KMIP_TYPE_STRUCTURE) {
      // Guard: the declared structure body must fit within the available
      // buffer.
      if (offset + length > data.size()) {
        throw KmipException("Buffer too short for structure body");
      }

      // Narrow the view to exactly the declared structure body so that a
      // malformed child cannot silently consume bytes that belong to a
      // sibling or a parent structure.  std::span::subspan is O(1) —
      // pointer + size only, no allocation, no copy.
      const auto struct_view = data.subspan(0, offset + length);

      auto struct_elem = std::make_shared<Element>();
      struct_elem->tag = static_cast<Tag>(tag);
      struct_elem->type = type;
      struct_elem->value = Structure{};

      std::size_t current_struct_offset = 0;
      while (current_struct_offset < length) {
        std::size_t item_offset = offset;
        auto child = deserialize_impl(struct_view, item_offset, depth + 1);
        std::get<Structure>(struct_elem->value).add(child);
        std::size_t consumed = item_offset - offset;
        current_struct_offset += consumed;
        offset = item_offset;
      }
      return struct_elem;
    } else {
      if (offset + padded_length > data.size()) {
        throw KmipException("Buffer too short for value");
      }

      auto elem = std::make_shared<Element>();
      elem->tag = static_cast<Tag>(tag);
      elem->type = type;

      switch (type) {
        case Type::KMIP_TYPE_INTEGER: {
          if (length != 4) {
            throw KmipException("Invalid length for Integer");
          }
          std::int32_t val;
          std::uint32_t raw = read_be_u32(data, offset);
          // raw is equivalent to big-endian read
          // we can just use memcpy if valid but manual reconstruction is safer
          // for endianness Actually raw is correct for big endian 4 bytes
          std::memcpy(&val, &raw, 4);  // Interpreting uint32 as int32
          elem->value = Integer{val};
          break;
        }
        case Type::KMIP_TYPE_LONG_INTEGER: {
          if (length != 8) {
            throw KmipException("Invalid length for Long Integer");
          }
          std::uint64_t raw = read_be_u64(data, offset);
          std::int64_t val;
          std::memcpy(&val, &raw, 8);
          elem->value = LongInteger{val};
          break;
        }
        case Type::KMIP_TYPE_BOOLEAN: {
          if (length != 8) {
            throw KmipException("Invalid length for Boolean");
          }
          std::uint64_t raw = read_be_u64(data, offset);
          // KMIP 1.4 §9.1.1.4.6: a Boolean must encode exactly 0 or 1.
          if (raw != 0 && raw != 1) {
            throw KmipException("Non-canonical Boolean TTLV value");
          }
          elem->value = Boolean{raw == 1};
          break;
        }
        case Type::KMIP_TYPE_ENUMERATION: {
          if (length != 4) {
            throw KmipException("Invalid length for Enumeration");
          }
          std::uint32_t raw = read_be_u32(data, offset);
          elem->value = Enumeration{static_cast<std::int32_t>(raw)};
          break;
        }
        case Type::KMIP_TYPE_TEXT_STRING: {
          // Copied straight into zeroed-on-free storage and moved into the
          // variant, without a plain std::string in between.
          const auto value_view = data.subspan(offset, length);
          elem->value =
              TextString{secure_string(value_view.begin(), value_view.end())};
          break;
        }
        case Type::KMIP_TYPE_BYTE_STRING: {
          const auto value_view = data.subspan(offset, length);
          elem->value =
              ByteString{secure_bytes(value_view.begin(), value_view.end())};
          break;
        }
        case Type::KMIP_TYPE_DATE_TIME: {
          if (length != 8) {
            throw KmipException("Invalid length for DateTime");
          }
          std::uint64_t raw = read_be_u64(data, offset);
          std::int64_t val;
          std::memcpy(&val, &raw, 8);
          elem->value = DateTime{val};
          break;
        }
        case Type::KMIP_TYPE_INTERVAL: {
          if (length != 4) {
            throw KmipException("Invalid length for Interval");
          }
          std::uint32_t raw = read_be_u32(data, offset);
          elem->value = Interval{raw};
          break;
        }
        case Type::KMIP_TYPE_BIG_INTEGER: {
          const auto value_view = data.subspan(offset, length);
          elem->value =
              BigInteger{secure_bytes(value_view.begin(), value_view.end())};
          break;
        }
        case Type::KMIP_TYPE_DATE_TIME_EXTENDED: {
          // KMIP 2.0: microseconds since Unix epoch, 8-byte big-endian int64.
          if (length != 8) {
            throw KmipException("Invalid length for DateTimeExtended");
          }
          std::uint64_t raw = read_be_u64(data, offset);
          std::int64_t val;
          std::memcpy(&val, &raw, 8);
          elem->value = DateTimeExtended{val};
          break;
        }
        default:
          throw KmipException(
              "Unknown type " + std::to_string(static_cast<std::uint32_t>(type))
          );
      }

      validate_zero_padding(data, offset, length, padded_length);
      offset += padded_length;
      return elem;
    }
  }

  std::shared_ptr<Element> Element::deserialize(
      std::span<const std::uint8_t> data, std::size_t &offset
  ) {
    return deserialize_impl(data, offset, 0);
  }

  // Factory methods
  std::shared_ptr<Element> Element::createStructure(Tag t) {
    return std::make_shared<Element>(
        t, static_cast<Type>(KMIP_TYPE_STRUCTURE), Structure{}
    );
  }
  std::shared_ptr<Element> Element::createInteger(Tag t, std::int32_t v) {
    return std::make_shared<Element>(
        t, static_cast<Type>(KMIP_TYPE_INTEGER), Integer{v}
    );
  }
  std::shared_ptr<Element> Element::createLongInteger(Tag t, std::int64_t v) {
    return std::make_shared<Element>(
        t, static_cast<Type>(KMIP_TYPE_LONG_INTEGER), LongInteger{v}
    );
  }
  std::shared_ptr<Element> Element::createBoolean(Tag t, bool v) {
    return std::make_shared<Element>(
        t, static_cast<Type>(KMIP_TYPE_BOOLEAN), Boolean{v}
    );
  }
  std::shared_ptr<Element> Element::createEnumeration(Tag t, std::int32_t v) {
    return std::make_shared<Element>(
        t, static_cast<Type>(KMIP_TYPE_ENUMERATION), Enumeration{v}
    );
  }
  std::shared_ptr<Element>
      Element::createTextString(Tag t, std::string_view v) {
    return std::make_shared<Element>(
        t,
        static_cast<Type>(KMIP_TYPE_TEXT_STRING),
        TextString{secure_string(v.begin(), v.end())}
    );
  }
  std::shared_ptr<Element>
      Element::createByteString(Tag t, std::span<const std::uint8_t> v) {
    return std::make_shared<Element>(
        t,
        static_cast<Type>(KMIP_TYPE_BYTE_STRING),
        ByteString{secure_bytes(v.begin(), v.end())}
    );
  }
  std::shared_ptr<Element>
      Element::createByteString(Tag t, std::initializer_list<std::uint8_t> v) {
    return createByteString(t, std::span<const std::uint8_t>(v));
  }
  std::shared_ptr<Element> Element::createDateTime(Tag t, std::int64_t v) {
    return std::make_shared<Element>(
        t, static_cast<Type>(KMIP_TYPE_DATE_TIME), DateTime{v}
    );
  }
  std::shared_ptr<Element>
      Element::createDateTimeExtended(Tag t, std::int64_t v) {
    return std::make_shared<Element>(
        t, static_cast<Type>(KMIP_TYPE_DATE_TIME_EXTENDED), DateTimeExtended{v}
    );
  }
  std::shared_ptr<Element> Element::createInterval(Tag t, std::uint32_t v) {
    return std::make_shared<Element>(
        t, static_cast<Type>(KMIP_TYPE_INTERVAL), Interval{v}
    );
  }
  std::shared_ptr<Element>
      Element::createBigInteger(Tag t, std::span<const std::uint8_t> v) {
    return std::make_shared<Element>(
        t,
        static_cast<Type>(KMIP_TYPE_BIG_INTEGER),
        BigInteger{secure_bytes(v.begin(), v.end())}
    );
  }
  std::shared_ptr<Element>
      Element::createBigInteger(Tag t, std::initializer_list<std::uint8_t> v) {
    return createBigInteger(t, std::span<const std::uint8_t>(v));
  }

  // Helper accessors
  Structure *Element::asStructure() {
    return std::get_if<Structure>(&value);
  }
  const Structure *Element::asStructure() const {
    return std::get_if<Structure>(&value);
  }

  std::shared_ptr<Element> Structure::find(Tag child_tag) const {
    for (const auto &item : items) {
      if (item->tag == child_tag) {
        return item;
      }
    }
    return nullptr;
  }

  std::vector<std::shared_ptr<Element>>
      Structure::findAll(Tag child_tag) const {
    std::vector<std::shared_ptr<Element>> matches;
    for (const auto &item : items) {
      if (item->tag == child_tag) {
        matches.push_back(item);
      }
    }
    return matches;
  }

  std::shared_ptr<Element> Element::getChild(Tag child_tag) const {
    const auto *s = std::get_if<Structure>(&value);
    if (!s) {
      return nullptr;
    }
    return s->find(child_tag);
  }

  std::vector<std::shared_ptr<Element>>
      Element::getChildren(Tag child_tag) const {
    const auto *s = std::get_if<Structure>(&value);
    if (!s) {
      return {};
    }
    return s->findAll(child_tag);
  }

  int32_t Element::toInt() const {
    if (auto *v = std::get_if<Integer>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not Integer");
  }

  int64_t Element::toLong() const {
    if (auto *v = std::get_if<LongInteger>(&value)) {
      return v->value;
    }
    if (auto *v = std::get_if<DateTime>(&value)) {
      return v->value;
    }
    if (auto *v = std::get_if<DateTimeExtended>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not Long/DateTime/DateTimeExtended");
  }

  bool Element::toBool() const {
    if (auto *v = std::get_if<Boolean>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not Boolean");
  }

  std::string Element::toString() const {
    return std::string(stringView());
  }

  std::vector<uint8_t> Element::toBytes() const {
    const auto bytes = bytesView();
    return {bytes.begin(), bytes.end()};
  }

  std::string_view Element::stringView() const {
    if (auto *v = std::get_if<TextString>(&value)) {
      return {v->value.data(), v->value.size()};
    }
    throw KmipException("Element is not TextString");
  }

  std::span<const uint8_t> Element::bytesView() const {
    if (auto *v = std::get_if<ByteString>(&value)) {
      return v->value;
    }
    if (auto *v = std::get_if<BigInteger>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not ByteString/BigInteger");
  }

  int32_t Element::toEnum() const {
    if (auto *v = std::get_if<Enumeration>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not Enumeration");
  }

  uint32_t Element::toInterval() const {
    if (auto *v = std::get_if<Interval>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not Interval");
  }

}  // namespace kmipcore
