/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/attributes_parser.hpp"

#include "kmipcore/kmip_attribute_names.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace kmipcore {

  namespace {

    [[nodiscard]] std::string date_to_string(int64_t seconds) {
      const auto t = static_cast<std::time_t>(seconds);
      std::tm tm_buf{};
#ifdef _WIN32
      gmtime_s(&tm_buf, &t);
#else
      gmtime_r(&t, &tm_buf);
#endif
      std::ostringstream oss;
      oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
      return oss.str();
    }

    [[nodiscard]] std::string bytes_to_hex(const std::vector<uint8_t> &bytes) {
      std::ostringstream oss;
      oss << std::uppercase << std::hex << std::setfill('0');
      for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) {
          oss << ' ';
        }
        oss << std::setw(2) << static_cast<int>(bytes[i]);
      }
      return oss.str();
    }

    [[nodiscard]] std::string generic_name_for_tag(Tag tag_value) {
      std::ostringstream oss;
      oss << "Tag(0x" << std::uppercase << std::hex << std::setfill('0')
          << std::setw(6) << static_cast<uint32_t>(tag_value) << ")";
      return oss.str();
    }

    /** Store one KMIP attribute element into @p result, preserving native types
     *  for user-defined / generic attributes. */
    void store_generic(
        Attributes &result,
        const std::string &name,
        const std::shared_ptr<Element> &value
    ) {
      if (!value) {
        return;
      }
      switch (value->type) {
        case type::KMIP_TYPE_TEXT_STRING:
          result.set(name, value->toString());
          break;
        case type::KMIP_TYPE_INTEGER:
          // Routes well-known names (Length, Mask) to typed setters; others go
          // to generic.
          result.set(name, value->toInt());
          break;
        case type::KMIP_TYPE_ENUMERATION:
          // Routes well-known names (Algorithm, State) to typed setters.
          result.set(name, value->toEnum());
          break;
        case type::KMIP_TYPE_LONG_INTEGER:
          result.set(name, value->toLong());
          break;
        case type::KMIP_TYPE_DATE_TIME:
          // Store as ISO 8601 string — dates are primarily for display.
          result.set(name, date_to_string(value->toLong()));
          break;
        case type::KMIP_TYPE_DATE_TIME_EXTENDED:
          // Extended timestamps are sub-second and are best preserved
          // numerically.
          result.set(name, value->toLong());
          break;
        case type::KMIP_TYPE_BOOLEAN:
          result.set(name, value->toBool());
          break;
        case type::KMIP_TYPE_BYTE_STRING:
        case type::KMIP_TYPE_BIG_INTEGER:
          result.set(name, bytes_to_hex(value->toBytes()));
          break;
        case type::KMIP_TYPE_INTERVAL:
          result.set(name, static_cast<int64_t>(value->toInterval()));
          break;
        case type::KMIP_TYPE_STRUCTURE:
          // Name attribute: extract the NameValue child.
          if (auto name_val = value->getChild(tag::KMIP_TAG_NAME_VALUE);
              name_val) {
            result.set(name, name_val->toString());
          } else {
            result.set(name, std::string("<STRUCTURE>"));
          }
          break;
        default:
          break;
      }
    }

    /**
     * @brief Parses a single KMIP 2.0 typed attribute element (not an Attribute
     *        name/value wrapper) and stores its value in @p result.
     *
     * KMIP 2.0 returns attributes as specific tagged elements inside an
     * Attributes container, e.g. KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM rather than
     * an Attribute structure with Attribute Name = "Cryptographic Algorithm".
     */
    void parse_v2_typed_attribute(
        Attributes &result, const std::shared_ptr<Element> &elem
    ) {
      if (!elem) {
        return;
      }

      switch (elem->tag) {
        case tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
          result.set_algorithm(checked_cryptographic_algorithm(elem->toEnum()));
          break;
        case tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH:
          result.set_crypto_length(elem->toInt());
          break;
        case tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK:
          result.set_usage_mask(
              static_cast<cryptographic_usage_mask>(elem->toInt())
          );
          break;
        case tag::KMIP_TAG_STATE:
          result.set_state(checked_state(elem->toEnum()));
          break;
        case tag::KMIP_TAG_NAME:
          // Name is a Structure: { Name Value (TextString), Name Type (Enum) }
          if (const auto name_val = elem->getChild(tag::KMIP_TAG_NAME_VALUE);
              name_val) {
            result.set(std::string(KMIP_ATTR_NAME_NAME), name_val->toString());
          }
          break;
        case tag::KMIP_TAG_OBJECT_GROUP:
          result.set(std::string(KMIP_ATTR_NAME_GROUP), elem->toString());
          break;
        case tag::KMIP_TAG_UNIQUE_IDENTIFIER:
          result.set(
              std::string(KMIP_ATTR_NAME_UNIQUE_IDENTIFIER), elem->toString()
          );
          break;
        case tag::KMIP_TAG_ACTIVATION_DATE:
          result.set(
              std::string(KMIP_ATTR_NAME_ACTIVATION_DATE),
              date_to_string(elem->toLong())
          );
          break;
        case tag::KMIP_TAG_DEACTIVATION_DATE:
          result.set(
              std::string(KMIP_ATTR_NAME_DEACTIVATION_DATE),
              date_to_string(elem->toLong())
          );
          break;
        case tag::KMIP_TAG_PROCESS_START_DATE:
          result.set(
              std::string(KMIP_ATTR_NAME_PROCESS_START_DATE),
              date_to_string(elem->toLong())
          );
          break;
        case tag::KMIP_TAG_PROTECT_STOP_DATE:
          result.set(
              std::string(KMIP_ATTR_NAME_PROTECT_STOP_DATE),
              date_to_string(elem->toLong())
          );
          break;
        default:
          // Preserve unknown or currently-unmapped KMIP 2.0 typed attributes
          // instead of silently dropping them.
          switch (elem->type) {
            case type::KMIP_TYPE_TEXT_STRING:
              result.set(generic_name_for_tag(elem->tag), elem->toString());
              break;
            case type::KMIP_TYPE_INTEGER:
              result.set(generic_name_for_tag(elem->tag), elem->toInt());
              break;
            case type::KMIP_TYPE_ENUMERATION:
              result.set(generic_name_for_tag(elem->tag), elem->toEnum());
              break;
            case type::KMIP_TYPE_LONG_INTEGER:
            case type::KMIP_TYPE_DATE_TIME:
            case type::KMIP_TYPE_DATE_TIME_EXTENDED:
              result.set(generic_name_for_tag(elem->tag), elem->toLong());
              break;
            case type::KMIP_TYPE_BOOLEAN:
              result.set(generic_name_for_tag(elem->tag), elem->toBool());
              break;
            case type::KMIP_TYPE_BYTE_STRING:
            case type::KMIP_TYPE_BIG_INTEGER:
              result.set(
                  generic_name_for_tag(elem->tag), bytes_to_hex(elem->toBytes())
              );
              break;
            case type::KMIP_TYPE_INTERVAL:
              result.set(
                  generic_name_for_tag(elem->tag),
                  static_cast<int64_t>(elem->toInterval())
              );
              break;
            case type::KMIP_TYPE_STRUCTURE:
              result.set(
                  generic_name_for_tag(elem->tag), std::string("<STRUCTURE>")
              );
              break;
            default:
              break;
          }
          break;
      }
    }

  }  // namespace

  Attributes AttributesParser::parse(
      const std::vector<std::shared_ptr<Element>> &attributes
  ) {
    Attributes result;

    for (const auto &attribute : attributes) {
      if (!attribute) {
        continue;
      }

      // ---- KMIP 1.x: Attribute structure with Attribute Name + Attribute
      // Value ----
      if (attribute->tag == tag::KMIP_TAG_ATTRIBUTE) {
        auto attr_name_elem = attribute->getChild(tag::KMIP_TAG_ATTRIBUTE_NAME);
        auto attr_value_elem =
            attribute->getChild(tag::KMIP_TAG_ATTRIBUTE_VALUE);
        if (!attr_name_elem) {
          continue;
        }

        const auto raw_name = attr_name_elem->toString();

        if (raw_name == "Cryptographic Algorithm") {
          if (attr_value_elem) {
            result.set_algorithm(
                checked_cryptographic_algorithm(attr_value_elem->toEnum())
            );
          }
          continue;
        }
        if (raw_name == "Cryptographic Length") {
          if (attr_value_elem) {
            result.set_crypto_length(attr_value_elem->toInt());
          }
          continue;
        }
        if (raw_name == "Cryptographic Usage Mask") {
          if (attr_value_elem) {
            result.set_usage_mask(
                static_cast<cryptographic_usage_mask>(attr_value_elem->toInt())
            );
          }
          continue;
        }
        if (raw_name == "State") {
          if (attr_value_elem) {
            result.set_state(checked_state(attr_value_elem->toEnum()));
          }
          continue;
        }

        // ---- Legacy name normalisation ----
        const std::string name =
            (raw_name == "UniqueID")
                ? std::string(KMIP_ATTR_NAME_UNIQUE_IDENTIFIER)
                : raw_name;

        // ---- All other 1.x attributes: preserve native type in generic map
        // ----
        store_generic(result, name, attr_value_elem);
        continue;
      }

      // ---- KMIP 2.0: typed element with a specific KMIP tag ----
      parse_v2_typed_attribute(result, attribute);
    }

    return result;
  }

}  // namespace kmipcore
