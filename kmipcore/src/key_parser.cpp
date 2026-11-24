/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/key_parser.hpp"

#include "kmipcore/attributes_parser.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_errors.hpp"

namespace kmipcore {

  namespace {

    /** Copies Key Material straight into zeroed-on-free memory. toBytes()
     * would return another, plain copy of the key that is never zeroed. */
    secure_bytes secure_key_material(const Element &key_material) {
      const auto *bytes = std::get_if<ByteString>(&key_material.value);
      if (!bytes) {
        throw KmipException(
            KMIP_INVALID_ENCODING, "Key Material is not a byte string."
        );
      }
      return secure_bytes(bytes->value.begin(), bytes->value.end());
    }

    /** Extract a Key from an element that contains a KeyBlock (Symmetric Key,
     * Private Key, Public Key). */
    Key parse_key_from_key_block_holder(
        const std::shared_ptr<Element> &object_element,
        KeyType key_type,
        const char *type_name
    ) {
      auto key_block = object_element->getChild(tag::KMIP_TAG_KEY_BLOCK);
      if (!key_block) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            std::string("Missing Key Block in ") + type_name + " response."
        );
      }

      auto key_value = key_block->getChild(tag::KMIP_TAG_KEY_VALUE);
      if (!key_value) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            std::string("Missing Key Value in ") + type_name + " response."
        );
      }

      auto key_material = key_value->getChild(tag::KMIP_TAG_KEY_MATERIAL);
      if (!key_material) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            std::string("Missing Key Material in ") + type_name + " response."
        );
      }

      // REQUIRED in a Key Block (KMIP 1.4 §2.1.3 Table 7, 2.0 §3.1).
      auto key_format = key_block->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE);
      if (!key_format) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            std::string("Missing Key Format Type in ") + type_name +
                " response."
        );
      }
      // Transparent Key Format Types hold a structure of key components
      // (1.4 §2.1.7), which this library does not convert to bytes.
      if (key_material->asStructure()) {
        throw KmipException(
            KMIP_NOT_IMPLEMENTED,
            std::string("Key Material of the ") + type_name +
                " is a structure (Key Format Type " +
                std::to_string(key_format->toEnum()) +
                "); only byte-string Key Format Types are supported."
        );
      }

      secure_bytes kv = secure_key_material(*key_material);

      // Parse attributes from the key value's Attribute children.
      Attributes key_attrs = AttributesParser::parse(
          key_value->getChildren(tag::KMIP_TAG_ATTRIBUTE)
      );

      // Algorithm and Length may also appear directly in the Key Block.
      if (auto alg_elem =
              key_block->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM)) {
        key_attrs.set_algorithm(
            checked_cryptographic_algorithm(alg_elem->toEnum())
        );
      }
      if (auto len_elem =
              key_block->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH)) {
        key_attrs.set_crypto_length(len_elem->toInt());
      }

      if (key_type == KeyType::SYMMETRIC_KEY) {
        KeyParser::checkSymmetricKeyMaterial(
            kv, key_format->toEnum(), key_attrs
        );
      }

      Key key(kv, key_type, std::move(key_attrs));
      key.set_key_format(key_format->toEnum());
      return key;
    }

  }  // anonymous namespace

  void KeyParser::checkSymmetricKeyMaterial(
      std::span<const unsigned char> material,
      int32_t key_format,
      const Attributes &attributes
  ) {
    if (material.empty()) {
      throw KmipException(
          KMIP_INVALID_ENCODING, "Key Material of the Symmetric Key is empty."
      );
    }
    const auto length = attributes.crypto_length();
    if (key_format != KMIP_KEYFORMAT_RAW || !length.has_value()) {
      return;
    }
    // 64-bit: the length comes from the server and may be anything.
    const int64_t stated = *length;
    const auto bits = static_cast<int64_t>(material.size()) * 8;
    const auto algorithm = attributes.algorithm();
    const bool parity_allowed =
        algorithm == cryptographic_algorithm::KMIP_CRYPTOALG_DES ||
        algorithm == cryptographic_algorithm::KMIP_CRYPTOALG_TRIPLE_DES;
    if (bits == stated ||
        (parity_allowed && stated % 7 == 0 && bits == stated / 7 * 8)) {
      return;
    }
    throw KmipException(
        KMIP_INVALID_ENCODING,
        "Key Material of the Symmetric Key has " + std::to_string(bits) +
            " bits, but its Cryptographic Length is " + std::to_string(stated) +
            "."
    );
  }

  Key KeyParser::parseGetKeyResponse(const GetResponseBatchItem &item) {
    return parseResponse(item.getResponsePayload());
  }

  std::optional<int32_t>
      KeyParser::keyFormatType(const GetResponseBatchItem &item) {
    const auto object = item.getObjectElement();
    const auto key_block =
        object ? object->getChild(tag::KMIP_TAG_KEY_BLOCK) : nullptr;
    const auto key_format =
        key_block ? key_block->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE)
                  : nullptr;
    if (!key_format) {
      return std::nullopt;
    }
    return key_format->toEnum();
  }

  Secret KeyParser::parseGetSecretResponse(const GetResponseBatchItem &item) {
    if (item.getObjectType() != KMIP_OBJTYPE_SECRET_DATA) {
      throw KmipException(
          KMIP_REASON_INVALID_DATA_TYPE, "Secret data expected in Get response."
      );
    }

    auto object = item.getObjectElement();
    if (!object) {
      throw KmipException(
          KMIP_INVALID_ENCODING, "Missing Secret Data object in response."
      );
    }

    auto secret_type = object->getChild(tag::KMIP_TAG_SECRET_DATA_TYPE);
    auto key_block = object->getChild(tag::KMIP_TAG_KEY_BLOCK);
    if (!secret_type || !key_block) {
      throw KmipException(
          KMIP_INVALID_ENCODING, "Secret data key block format mismatch"
      );
    }

    auto key_format = key_block->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE);
    if (!key_format || (key_format->toEnum() != KMIP_KEYFORMAT_OPAQUE &&
                        key_format->toEnum() != KMIP_KEYFORMAT_RAW)) {
      throw KmipException(
          KMIP_OBJECT_MISMATCH, "Secret data key block format mismatch"
      );
    }

    auto key_value = key_block->getChild(tag::KMIP_TAG_KEY_VALUE);
    if (!key_value) {
      throw KmipException(KMIP_INVALID_ENCODING, "Missing secret key value.");
    }

    auto key_material = key_value->getChild(tag::KMIP_TAG_KEY_MATERIAL);
    if (!key_material) {
      throw KmipException(
          KMIP_INVALID_ENCODING, "Missing secret key material."
      );
    }

    Secret secret;
    secret.set_value(secure_key_material(*key_material));
    secret.set_secret_type(checked_secret_data_type(secret_type->toEnum()));
    return secret;
  }

  Key KeyParser::parseResponse(const std::shared_ptr<Element> &payload) {
    if (payload == nullptr) {
      throw KmipException(KMIP_INVALID_ENCODING, "Missing response payload.");
    }

    auto object_type = payload->getChild(tag::KMIP_TAG_OBJECT_TYPE);
    if (!object_type) {
      throw KmipException(
          KMIP_INVALID_ENCODING, "Missing Object Type in Get response."
      );
    }

    // Map KMIP object type to wrapper tag, KeyType, and human-readable name.
    struct ObjectTypeMapping {
      int32_t obj_type;
      int32_t wrapper_tag;
      KeyType key_type;
      const char *name;
    };
    static constexpr ObjectTypeMapping mappings[] = {
        {KMIP_OBJTYPE_SYMMETRIC_KEY,
         KMIP_TAG_SYMMETRIC_KEY,
         KeyType::SYMMETRIC_KEY,
         "Symmetric Key"},
        {KMIP_OBJTYPE_PRIVATE_KEY,
         KMIP_TAG_PRIVATE_KEY,
         KeyType::PRIVATE_KEY,
         "Private Key"},
        {KMIP_OBJTYPE_PUBLIC_KEY,
         KMIP_TAG_PUBLIC_KEY,
         KeyType::PUBLIC_KEY,
         "Public Key"},
    };

    const auto obj_type_val = object_type->toEnum();

    for (const auto &m : mappings) {
      if (obj_type_val != m.obj_type) {
        continue;
      }

      auto object_element = payload->getChild(static_cast<Tag>(m.wrapper_tag));
      if (!object_element) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            std::string("Missing ") + m.name + " object in Get response."
        );
      }

      // Symmetric keys require RAW format
      if (m.obj_type == KMIP_OBJTYPE_SYMMETRIC_KEY) {
        auto key_block = object_element->getChild(tag::KMIP_TAG_KEY_BLOCK);
        if (key_block) {
          auto key_format = key_block->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE);
          if (!key_format || key_format->toEnum() != KMIP_KEYFORMAT_RAW) {
            throw KmipException(
                KMIP_INVALID_ENCODING, "Invalid response object format."
            );
          }
        }
      }

      return parse_key_from_key_block_holder(
          object_element, m.key_type, m.name
      );
    }

    if (obj_type_val == KMIP_OBJTYPE_CERTIFICATE) {
      throw KmipException(
          KMIP_NOT_IMPLEMENTED,
          "Certificate object type parsing is not yet supported."
      );
    }

    throw KmipException(
        KMIP_NOT_IMPLEMENTED,
        std::string("Unsupported object type: ") + std::to_string(obj_type_val)
    );
  }

}  // namespace kmipcore
