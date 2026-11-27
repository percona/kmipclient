/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/kmip_formatter.hpp"

#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/kmip_protocol.hpp"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>

namespace kmipcore {

  namespace {

    [[nodiscard]] std::string indent(size_t level) {
      std::string s(level * 2, ' ');
      return s;
    }

    [[nodiscard]] std::string
        format_hex_uint(uint64_t value, std::streamsize width = 0) {
      std::ostringstream oss;
      oss << "0x" << std::uppercase << std::hex << std::setfill('0');
      const auto bounded_width = std::max<std::streamsize>(
          0, std::min<std::streamsize>(width, std::numeric_limits<int>::max())
      );
      oss << std::setw(static_cast<int>(bounded_width));
      oss << value;
      return oss.str();
    }

    [[nodiscard]] std::string format_bytes_hex(std::span<const uint8_t> bytes) {
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

    [[nodiscard]] std::string quote_string(std::string_view value) {
      std::ostringstream oss;
      oss << '"';
      for (const char ch : value) {
        switch (ch) {
          case '\\':
            oss << "\\\\";
            break;
          case '"':
            oss << "\\\"";
            break;
          case '\n':
            oss << "\\n";
            break;
          case '\r':
            oss << "\\r";
            break;
          case '\t':
            oss << "\\t";
            break;
          default:
            oss << ch;
            break;
        }
      }
      oss << '"';
      return oss.str();
    }

    [[nodiscard]] std::string format_datetime(int64_t seconds) {
      const auto t = static_cast<std::time_t>(seconds);
      std::tm tm_buf{};
#if defined(_WIN32)
      gmtime_s(&tm_buf, &t);
#else
      gmtime_r(&t, &tm_buf);
#endif
      std::ostringstream oss;
      oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ") << " (" << seconds
          << ')';
      return oss.str();
    }

    [[nodiscard]] const char *type_name(Type type) {
      switch (static_cast<std::uint32_t>(type)) {
        case KMIP_TYPE_STRUCTURE:
          return "Structure";
        case KMIP_TYPE_INTEGER:
          return "Integer";
        case KMIP_TYPE_LONG_INTEGER:
          return "LongInteger";
        case KMIP_TYPE_BIG_INTEGER:
          return "BigInteger";
        case KMIP_TYPE_ENUMERATION:
          return "Enumeration";
        case KMIP_TYPE_BOOLEAN:
          return "Boolean";
        case KMIP_TYPE_TEXT_STRING:
          return "TextString";
        case KMIP_TYPE_BYTE_STRING:
          return "ByteString";
        case KMIP_TYPE_DATE_TIME:
          return "DateTime";
        case KMIP_TYPE_INTERVAL:
          return "Interval";
        case KMIP_TYPE_DATE_TIME_EXTENDED:
          return "DateTimeExtended";
        default:
          return "UnknownType";
      }
    }

    [[nodiscard]] bool is_sensitive_tag(Tag tag) {
      switch (tag) {
        case Tag::KMIP_TAG_CREDENTIAL_VALUE:
        case Tag::KMIP_TAG_IV_COUNTER_NONCE:
        case Tag::KMIP_TAG_KEY_MATERIAL:
        case Tag::KMIP_TAG_KEY_VALUE:
        case Tag::KMIP_TAG_MAC_SIGNATURE:
        case Tag::KMIP_TAG_NONCE_VALUE:
        case Tag::KMIP_TAG_PASSWORD:
        case Tag::KMIP_TAG_SALT:
        case Tag::KMIP_TAG_SECRET_DATA:
        case Tag::KMIP_TAG_USERNAME:
          return true;
        default:
          return false;
      }
    }

    [[nodiscard]] bool should_redact_subtree(const Element &element) {
      if (!is_sensitive_tag(element.tag)) {
        return false;
      }
      return element.type == Type::KMIP_TYPE_STRUCTURE;
    }

    [[nodiscard]] std::optional<std::size_t>
        redacted_value_length(const Element &element) {
      switch (static_cast<std::uint32_t>(element.type)) {
        case KMIP_TYPE_BIG_INTEGER:
        case KMIP_TYPE_BYTE_STRING:
          return element.bytesView().size();
        case KMIP_TYPE_TEXT_STRING:
          return element.stringView().size();
        default:
          return std::nullopt;
      }
    }

    [[nodiscard]] std::string redacted_value_summary(const Element &element) {
      std::ostringstream oss;
      oss << "<redacted sensitive " << type_name(element.type);
      if (const auto len = redacted_value_length(element); len.has_value()) {
        oss << ", len=" << *len;
      }
      oss << '>';
      return oss.str();
    }

    [[nodiscard]] const char *tag_name(Tag tag) {
      switch (static_cast<std::uint32_t>(tag)) {
        case KMIP_TAG_ATTRIBUTE:
          return "Attribute";
        case KMIP_TAG_ATTRIBUTE_NAME:
          return "AttributeName";
        case KMIP_TAG_ATTRIBUTE_VALUE:
          return "AttributeValue";
        case KMIP_TAG_BATCH_COUNT:
          return "BatchCount";
        case KMIP_TAG_BATCH_ITEM:
          return "BatchItem";
        case KMIP_TAG_BATCH_ORDER_OPTION:
          return "BatchOrderOption";
        case KMIP_TAG_COMPROMISE_OCCURRANCE_DATE:
          return "CompromiseOccurrenceDate";
        case KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
          return "CryptographicAlgorithm";
        case KMIP_TAG_CRYPTOGRAPHIC_LENGTH:
          return "CryptographicLength";
        case KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK:
          return "CryptographicUsageMask";
        case KMIP_TAG_KEY_BLOCK:
          return "KeyBlock";
        case KMIP_TAG_KEY_FORMAT_TYPE:
          return "KeyFormatType";
        case KMIP_TAG_KEY_MATERIAL:
          return "KeyMaterial";
        case KMIP_TAG_KEY_VALUE:
          return "KeyValue";
        case KMIP_TAG_LOCATED_ITEMS:
          return "LocatedItems";
        case KMIP_TAG_MAXIMUM_ITEMS:
          return "MaximumItems";
        case KMIP_TAG_MAXIMUM_RESPONSE_SIZE:
          return "MaximumResponseSize";
        case KMIP_TAG_NAME:
          return "Name";
        case KMIP_TAG_NAME_TYPE:
          return "NameType";
        case KMIP_TAG_NAME_VALUE:
          return "NameValue";
        case KMIP_TAG_OBJECT_GROUP:
          return "ObjectGroup";
        case KMIP_TAG_OBJECT_TYPE:
          return "ObjectType";
        case KMIP_TAG_OFFSET_ITEMS:
          return "OffsetItems";
        case KMIP_TAG_OPERATION:
          return "Operation";
        case KMIP_TAG_PROTOCOL_VERSION:
          return "ProtocolVersion";
        case KMIP_TAG_PROTOCOL_VERSION_MAJOR:
          return "ProtocolVersionMajor";
        case KMIP_TAG_PROTOCOL_VERSION_MINOR:
          return "ProtocolVersionMinor";
        case KMIP_TAG_REQUEST_HEADER:
          return "RequestHeader";
        case KMIP_TAG_REQUEST_MESSAGE:
          return "RequestMessage";
        case KMIP_TAG_REQUEST_PAYLOAD:
          return "RequestPayload";
        case KMIP_TAG_RESPONSE_HEADER:
          return "ResponseHeader";
        case KMIP_TAG_RESPONSE_MESSAGE:
          return "ResponseMessage";
        case KMIP_TAG_RESPONSE_PAYLOAD:
          return "ResponsePayload";
        case KMIP_TAG_RESULT_MESSAGE:
          return "ResultMessage";
        case KMIP_TAG_RESULT_REASON:
          return "ResultReason";
        case KMIP_TAG_RESULT_STATUS:
          return "ResultStatus";
        case KMIP_TAG_REVOKATION_MESSAGE:
          return "RevocationMessage";
        case KMIP_TAG_REVOCATION_REASON:
          return "RevocationReason";
        case KMIP_TAG_REVOCATION_REASON_CODE:
          return "RevocationReasonCode";
        case KMIP_TAG_SECRET_DATA:
          return "SecretData";
        case KMIP_TAG_SECRET_DATA_TYPE:
          return "SecretDataType";
        case KMIP_TAG_STATE:
          return "State";
        case KMIP_TAG_SYMMETRIC_KEY:
          return "SymmetricKey";
        case KMIP_TAG_TEMPLATE_ATTRIBUTE:
          return "TemplateAttribute";
        case KMIP_TAG_TIME_STAMP:
          return "TimeStamp";
        case KMIP_TAG_UNIQUE_BATCH_ITEM_ID:
          return "UniqueBatchItemId";
        case KMIP_TAG_UNIQUE_IDENTIFIER:
          return "UniqueIdentifier";
        case KMIP_TAG_USERNAME:
          return "Username";
        case KMIP_TAG_PASSWORD:
          return "Password";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *operation_name(int32_t value) {
      switch (value) {
        case KMIP_OP_CREATE:
          return "Create";
        case KMIP_OP_REGISTER:
          return "Register";
        case KMIP_OP_LOCATE:
          return "Locate";
        case KMIP_OP_GET:
          return "Get";
        case KMIP_OP_GET_ATTRIBUTES:
          return "GetAttributes";
        case KMIP_OP_GET_ATTRIBUTE_LIST:
          return "GetAttributeList";
        case KMIP_OP_ACTIVATE:
          return "Activate";
        case KMIP_OP_REVOKE:
          return "Revoke";
        case KMIP_OP_DESTROY:
          return "Destroy";
        case KMIP_OP_QUERY:
          return "Query";
        case KMIP_OP_DISCOVER_VERSIONS:
          return "DiscoverVersions";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *object_type_name(int32_t value) {
      switch (value) {
        case KMIP_OBJTYPE_CERTIFICATE:
          return "Certificate";
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
          return "SymmetricKey";
        case KMIP_OBJTYPE_PUBLIC_KEY:
          return "PublicKey";
        case KMIP_OBJTYPE_PRIVATE_KEY:
          return "PrivateKey";
        case KMIP_OBJTYPE_SECRET_DATA:
          return "SecretData";
        case KMIP_OBJTYPE_OPAQUE_OBJECT:
          return "OpaqueObject";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *result_status_name(int32_t value) {
      switch (value) {
        case KMIP_STATUS_SUCCESS:
          return "Success";
        case KMIP_STATUS_OPERATION_FAILED:
          return "OperationFailed";
        case KMIP_STATUS_OPERATION_PENDING:
          return "OperationPending";
        case KMIP_STATUS_OPERATION_UNDONE:
          return "OperationUndone";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *crypto_algorithm_name(int32_t value) {
      switch (value) {
        case KMIP_CRYPTOALG_DES:
          return "DES";
        case KMIP_CRYPTOALG_TRIPLE_DES:
          return "3DES";
        case KMIP_CRYPTOALG_AES:
          return "AES";
        case KMIP_CRYPTOALG_RSA:
          return "RSA";
        case KMIP_CRYPTOALG_DSA:
          return "DSA";
        case KMIP_CRYPTOALG_ECDSA:
          return "ECDSA";
        case KMIP_CRYPTOALG_HMAC_SHA1:
          return "HMAC-SHA1";
        case KMIP_CRYPTOALG_HMAC_SHA224:
          return "HMAC-SHA224";
        case KMIP_CRYPTOALG_HMAC_SHA256:
          return "HMAC-SHA256";
        case KMIP_CRYPTOALG_HMAC_SHA384:
          return "HMAC-SHA384";
        case KMIP_CRYPTOALG_HMAC_SHA512:
          return "HMAC-SHA512";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *name_type_name(int32_t value) {
      switch (value) {
        case KMIP_NAME_UNINTERPRETED_TEXT_STRING:
          return "UninterpretedTextString";
        case KMIP_NAME_URI:
          return "URI";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *key_format_type_name(int32_t value) {
      switch (value) {
        case KMIP_KEYFORMAT_RAW:
          return "Raw";
        case KMIP_KEYFORMAT_OPAQUE:
          return "Opaque";
        case KMIP_KEYFORMAT_PKCS1:
          return "PKCS1";
        case KMIP_KEYFORMAT_PKCS8:
          return "PKCS8";
        case KMIP_KEYFORMAT_X509:
          return "X509";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *secret_data_type_name(int32_t value) {
      switch (static_cast<secret_data_type>(value)) {
        case secret_data_type::KMIP_SECDATA_PASSWORD:
          return "Password";
        case secret_data_type::KMIP_SECDATA_SEED:
          return "Seed";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *revocation_reason_name(std::int32_t value) {
      switch (static_cast<revocation_reason_type>(
          static_cast<std::uint32_t>(value)
      )) {
        case revocation_reason_type::KMIP_REVOKE_UNSPECIFIED:
          return "Unspecified";
        case revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE:
          return "KeyCompromise";
        case revocation_reason_type::KMIP_REVOKE_CA_COMPROMISE:
          return "CACompromise";
        case revocation_reason_type::KMIP_REVOKE_AFFILIATION_CHANGED:
          return "AffiliationChanged";
        case revocation_reason_type::KMIP_REVOKE_SUSPENDED:
          return "Suspended";
        case revocation_reason_type::KMIP_REVOKE_CESSATION_OF_OPERATION:
          return "CessationOfOperation";
        case revocation_reason_type::KMIP_REVOKE_PRIVILEDGE_WITHDRAWN:
          return "PrivilegeWithdrawn";
        case revocation_reason_type::KMIP_REVOKE_EXTENSIONS:
          return "Extensions";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] std::string enum_value_name(Tag tag, std::int32_t value) {
      const char *name = nullptr;
      switch (tag) {
        case Tag::KMIP_TAG_OPERATION:
          name = operation_name(value);
          break;
        case Tag::KMIP_TAG_OBJECT_TYPE:
          name = object_type_name(value);
          break;
        case Tag::KMIP_TAG_RESULT_STATUS:
          name = result_status_name(value);
          break;
        case Tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
          name = crypto_algorithm_name(value);
          break;
        case Tag::KMIP_TAG_NAME_TYPE:
          name = name_type_name(value);
          break;
        case Tag::KMIP_TAG_KEY_FORMAT_TYPE:
          name = key_format_type_name(value);
          break;
        case Tag::KMIP_TAG_SECRET_DATA_TYPE:
          name = secret_data_type_name(value);
          break;
        case Tag::KMIP_TAG_STATE:
          name = state_to_string(static_cast<state>(value));
          break;
        case Tag::KMIP_TAG_REVOCATION_REASON_CODE:
          name = revocation_reason_name(value);
          break;
        default:
          break;
      }

      if (name != nullptr) {
        std::ostringstream oss;
        oss << name << " (" << value << ')';
        return oss.str();
      }

      std::ostringstream oss;
      oss << value << " / "
          << format_hex_uint(static_cast<std::uint32_t>(value), 8);
      return oss.str();
    }

    void format_element_impl(
        const std::shared_ptr<Element> &element,
        std::ostringstream &oss,
        std::size_t depth
    ) {
      if (!element) {
        oss << indent(depth) << "<null>\n";
        return;
      }

      const char *known_tag_name = tag_name(element->tag);
      oss << indent(depth)
          << (known_tag_name != nullptr ? known_tag_name : "UnknownTag") << " ("
          << format_hex_uint(static_cast<std::uint32_t>(element->tag), 6)
          << ") [" << type_name(element->type) << ']';

      if (should_redact_subtree(*element)) {
        oss << " = <redacted sensitive subtree>\n";
        return;
      }

      if (is_sensitive_tag(element->tag)) {
        oss << " = " << redacted_value_summary(*element) << '\n';
        return;
      }

      if (const auto *structure = element->asStructure();
          structure != nullptr) {
        oss << '\n';
        if (structure->items.empty()) {
          oss << indent(depth + 1) << "<empty>\n";
        }
        for (const auto &child : structure->items) {
          format_element_impl(child, oss, depth + 1);
        }
        return;
      }

      oss << " = ";
      switch (static_cast<std::uint32_t>(element->type)) {
        case KMIP_TYPE_INTEGER:
          oss << element->toInt();
          break;
        case KMIP_TYPE_LONG_INTEGER:
          oss << element->toLong();
          break;
        case KMIP_TYPE_BIG_INTEGER: {
          const auto value = element->bytesView();
          oss << "len=" << value.size() << ", hex=[" << format_bytes_hex(value)
              << ']';
          break;
        }
        case KMIP_TYPE_ENUMERATION:
          oss << enum_value_name(element->tag, element->toEnum());
          break;
        case KMIP_TYPE_BOOLEAN:
          oss << (element->toBool() ? "true" : "false");
          break;
        case KMIP_TYPE_TEXT_STRING:
          oss << quote_string(element->stringView());
          break;
        case KMIP_TYPE_BYTE_STRING: {
          const auto value = element->bytesView();
          oss << "len=" << value.size() << ", hex=[" << format_bytes_hex(value)
              << ']';
          break;
        }
        case KMIP_TYPE_DATE_TIME:
          oss << format_datetime(element->toLong());
          break;
        case KMIP_TYPE_INTERVAL:
          oss << element->toInterval();
          break;
        default:
          oss << "<unhandled>";
          break;
      }
      oss << '\n';
    }

  }  // namespace

  std::string format_element(const std::shared_ptr<Element> &element) {
    std::ostringstream oss;
    format_element_impl(element, oss, 0);
    return oss.str();
  }

  std::string format_request(const RequestMessage &request) {
    return format_element(request.toElement());
  }

  std::string format_response(const ResponseMessage &response) {
    return format_element(response.toElement());
  }

  std::string format_ttlv(std::span<const uint8_t> ttlv) {
    try {
      if (ttlv.empty()) {
        return "<empty KMIP TTLV>\n";
      }

      size_t offset = 0;
      auto root = Element::deserialize(ttlv, offset);
      auto formatted = format_element(root);
      if (offset != ttlv.size()) {
        std::ostringstream oss;
        oss << formatted << "Trailing bytes: " << (ttlv.size() - offset)
            << "\n";
        return oss.str();
      }
      return formatted;
    } catch (const std::exception &e) {
      std::ostringstream oss;
      oss << "Unable to format KMIP TTLV safely: " << e.what()
          << ". Raw payload omitted to avoid leaking sensitive data.\n";
      return oss.str();
    }
  }

  std::string usage_mask_to_string(std::uint32_t mask) {
    if (mask == 0) {
      return "UNSET";
    }

    std::ostringstream oss;
    bool first = true;

    // Define all known flags with their bit values (in order from KMIP spec)
    const struct {
      std::uint32_t bit;
      const char *name;
    } flags[] = {
        {0x00000001, "SIGN"},
        {0x00000002, "VERIFY"},
        {0x00000004, "ENCRYPT"},
        {0x00000008, "DECRYPT"},
        {0x00000010, "WRAP_KEY"},
        {0x00000020, "UNWRAP_KEY"},
        {0x00000040, "EXPORT"},
        {0x00000080, "MAC_GENERATE"},
        {0x00000100, "MAC_VERIFY"},
        {0x00000200, "DERIVE_KEY"},
        {0x00000400, "CONTENT_COMMITMENT"},
        {0x00000800, "KEY_AGREEMENT"},
        {0x00001000, "CERTIFICATE_SIGN"},
        {0x00002000, "CRL_SIGN"},
        {0x00004000, "GENERATE_CRYPTOGRAM"},
        {0x00008000, "VALIDATE_CRYPTOGRAM"},
        {0x00010000, "TRANSLATE_ENCRYPT"},
        {0x00020000, "TRANSLATE_DECRYPT"},
        {0x00040000, "TRANSLATE_WRAP"},
        {0x00080000, "TRANSLATE_UNWRAP"},
        {0x00100000, "AUTHENTICATE"},
        {0x00200000, "UNRESTRICTED"},
        {0x00400000, "FPE_ENCRYPT"},
        {0x00800000, "FPE_DECRYPT"},
    };

    std::uint32_t remaining = mask;
    for (const auto &flag : flags) {
      if ((mask & flag.bit) != 0) {
        if (!first) {
          oss << ", ";
        }
        oss << flag.name;
        first = false;
        remaining &= ~flag.bit;
      }
    }

    // If there are bits we don't recognize, add a notice
    if (remaining != 0) {
      if (!first) {
        oss << ", ";
      }
      oss << "UNKNOWN_BITS(" << std::hex << std::setfill('0') << std::setw(8)
          << remaining << ")";
    }

    return oss.str();
  }

}  // namespace kmipcore
