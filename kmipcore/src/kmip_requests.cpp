/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/kmip_requests.hpp"

#include "kmipcore/kmip_attribute_names.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <limits>
#include <string_view>
#include <unordered_set>

namespace kmipcore {

  namespace detail {
    [[nodiscard]] bool
        use_attributes_container(const ProtocolVersion &version) {
      return version.is_at_least(2, 0);
    }

    [[nodiscard]] std::optional<Tag>
        standard_attribute_name_to_tag(std::string_view name) {
      if (name == KMIP_ATTR_NAME_NAME) {
        return tag::KMIP_TAG_NAME;
      }
      if (name == KMIP_ATTR_NAME_GROUP) {
        return tag::KMIP_TAG_OBJECT_GROUP;
      }
      if (name == KMIP_ATTR_NAME_STATE) {
        return tag::KMIP_TAG_STATE;
      }
      if (name == KMIP_ATTR_NAME_UNIQUE_IDENTIFIER ||
          name == KMIP_ATTR_NAME_UNIQUE_IDENTIFIER_ALT) {
        return tag::KMIP_TAG_UNIQUE_IDENTIFIER;
      }
      if (name == KMIP_ATTR_NAME_ACTIVATION_DATE) {
        return tag::KMIP_TAG_ACTIVATION_DATE;
      }
      if (name == KMIP_ATTR_NAME_DEACTIVATION_DATE) {
        return tag::KMIP_TAG_DEACTIVATION_DATE;
      }
      if (name == KMIP_ATTR_NAME_PROCESS_START_DATE) {
        return tag::KMIP_TAG_PROCESS_START_DATE;
      }
      if (name == KMIP_ATTR_NAME_PROTECT_STOP_DATE) {
        return tag::KMIP_TAG_PROTECT_STOP_DATE;
      }
      if (name == KMIP_ATTR_NAME_CRYPTO_ALG) {
        return tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM;
      }
      if (name == KMIP_ATTR_NAME_CRYPTO_LEN) {
        return tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH;
      }
      if (name == KMIP_ATTR_NAME_CRYPTO_USAGE_MASK) {
        return tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK;
      }
      if (name == KMIP_ATTR_NAME_OPERATION_POLICY_NAME) {
        return tag::KMIP_TAG_OPERATION_POLICY_NAME;
      }
      return std::nullopt;
    }

    std::shared_ptr<Element>
        make_v2_attribute_reference(std::string_view attribute_name) {
      auto ref = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE_REFERENCE);
      if (const auto tag_value = standard_attribute_name_to_tag(attribute_name);
          tag_value.has_value()) {
        ref->asStructure()->add(
            Element::createEnumeration(
                tag::KMIP_TAG_ATTRIBUTE_REFERENCE,
                static_cast<int32_t>(*tag_value)
            )
        );
      } else {
        // Preserve interoperability with vendor-defined attributes by name.
        ref->asStructure()->add(
            Element::createTextString(
                tag::KMIP_TAG_ATTRIBUTE_NAME, std::string(attribute_name)
            )
        );
      }
      return ref;
    }

    std::shared_ptr<Element> make_text_attribute(
        const std::string &attribute_name, const std::string &value
    ) {
      auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
      attribute->asStructure()->add(
          Element::createTextString(
              tag::KMIP_TAG_ATTRIBUTE_NAME, attribute_name
          )
      );
      auto attribute_value =
          Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_VALUE, value);
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element>
        make_enum_attribute(const std::string &attribute_name, int32_t value) {
      auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
      attribute->asStructure()->add(
          Element::createTextString(
              tag::KMIP_TAG_ATTRIBUTE_NAME, attribute_name
          )
      );
      auto attribute_value =
          Element::createEnumeration(tag::KMIP_TAG_ATTRIBUTE_VALUE, value);
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element> make_integer_attribute(
        const std::string &attribute_name, int32_t value
    ) {
      auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
      attribute->asStructure()->add(
          Element::createTextString(
              tag::KMIP_TAG_ATTRIBUTE_NAME, attribute_name
          )
      );
      auto attribute_value =
          Element::createInteger(tag::KMIP_TAG_ATTRIBUTE_VALUE, value);
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element> make_name_attribute(const std::string &value) {
      auto attribute_value =
          Element::createStructure(tag::KMIP_TAG_ATTRIBUTE_VALUE);
      attribute_value->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_NAME_VALUE, value)
      );
      attribute_value->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_NAME_TYPE, KMIP_NAME_UNINTERPRETED_TEXT_STRING
          )
      );
      auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
      attribute->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "Name")
      );
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element> make_template_attribute(
        const std::vector<std::shared_ptr<Element>> &attributes
    ) {
      auto template_attribute =
          Element::createStructure(tag::KMIP_TAG_TEMPLATE_ATTRIBUTE);
      for (const auto &attribute : attributes) {
        template_attribute->asStructure()->add(attribute);
      }
      return template_attribute;
    }
    std::shared_ptr<Element>
        make_key_value(std::span<const unsigned char> bytes) {
      auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
      key_value->asStructure()->add(
          Element::createByteString(
              tag::KMIP_TAG_KEY_MATERIAL,
              std::vector<uint8_t>(bytes.begin(), bytes.end())
          )
      );
      return key_value;
    }
    std::shared_ptr<Element> make_key_block(
        int32_t key_format_type,
        std::span<const unsigned char> bytes,
        std::optional<int32_t> algorithm,
        std::optional<int32_t> cryptographic_length
    ) {
      auto key_block = Element::createStructure(tag::KMIP_TAG_KEY_BLOCK);
      key_block->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_KEY_FORMAT_TYPE, key_format_type
          )
      );
      key_block->asStructure()->add(make_key_value(bytes));
      if (algorithm) {
        key_block->asStructure()->add(
            Element::createEnumeration(
                tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, *algorithm
            )
        );
      }
      if (cryptographic_length) {
        key_block->asStructure()->add(
            Element::createInteger(
                tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, *cryptographic_length
            )
        );
      }
      return key_block;
    }
    // Highest Cryptographic Algorithm value a KMIP version defines: for 1.4
    // and 2.0 from their specs (SHAKE-256, 1.4 §9.1.3.2.13; Ed448, 2.0
    // §11.12), for earlier ones from the version notes in kmip_enums.hpp
    // (Twofish in 1.0, EC added in 1.2, One Time Pad in 1.3).
    int32_t last_crypto_algorithm(const ProtocolVersion &version) {
      using algorithm = cryptographic_algorithm;
      if (version.is_at_least(2, 0)) {
        return static_cast<int32_t>(algorithm::KMIP_CRYPTOALG_ED448);
      }
      if (version.is_at_least(1, 4)) {
        return static_cast<int32_t>(algorithm::KMIP_CRYPTOALG_SHAKE_256);
      }
      if (version.is_at_least(1, 3)) {
        return static_cast<int32_t>(algorithm::KMIP_CRYPTOALG_ONE_TIME_PAD);
      }
      if (version.is_at_least(1, 2)) {
        return static_cast<int32_t>(algorithm::KMIP_CRYPTOALG_EC);
      }
      return static_cast<int32_t>(algorithm::KMIP_CRYPTOALG_TWOFISH);
    }

    // Whether Register may send @p algorithm over @p version: a code the
    // version defines, or an Extensions value (8XXXXXXX, 1.4 §9.1.1.4,
    // 2.0 §10.1.2), which every version permits. An extension usually comes
    // from the server itself, on a key read back with Get, so it goes back
    // unchanged.
    bool algorithm_defined_in(
        cryptographic_algorithm algorithm, const ProtocolVersion &version
    ) {
      const auto value = static_cast<int32_t>(algorithm);
      return is_enumeration_extension(value) ||
             (value > 0 && value <= last_crypto_algorithm(version));
    }

    struct AlgorithmAndLength {
      int32_t algorithm;
      int32_t length;
    };

    // The Cryptographic Algorithm and Length to send for a key on Register,
    // or nullopt to send neither. In a Key Block they are both present or
    // both absent (1.4 §2.1.3 Table 7, 2.0 §3.1), and Register's attributes
    // get the same pair so the two never disagree. Neither is sent when:
    // - the algorithm is unknown, or not defined in the request's protocol
    //   version (e.g. Ed25519 over KMIP 1.4, see last_crypto_algorithm());
    // - the length is unknown. Only a Raw symmetric key's size is its key
    //   length; for an asymmetric key it is the size of the encoding.
    // A key encoding such as PKCS#8 or X.509 carries both, so the server can
    // still tell them (the Key Block rule allows leaving them out then).
    std::optional<AlgorithmAndLength>
        algorithm_and_length(const Key &key, const ProtocolVersion &version) {
      const auto algorithm = key.attributes().algorithm();
      if (algorithm == cryptographic_algorithm::KMIP_CRYPTOALG_UNSET ||
          !algorithm_defined_in(algorithm, version)) {
        return std::nullopt;
      }
      std::optional<int32_t> length = key.attributes().crypto_length();
      if (!length && key.type() == KeyType::SYMMETRIC_KEY &&
          key.value().size() <= static_cast<std::size_t>(
                                    std::numeric_limits<int32_t>::max() / 8
                                )) {
        length = static_cast<int32_t>(key.value().size() * 8);
      }
      if (!length || *length <= 0) {
        return std::nullopt;
      }
      return AlgorithmAndLength{static_cast<int32_t>(algorithm), *length};
    }

    // Why algorithm_and_length() has nothing to send for a symmetric key,
    // which Register then refuses.
    std::string symmetric_key_without_algorithm_and_length(
        const Key &key, const ProtocolVersion &version
    ) {
      const auto algorithm = key.attributes().algorithm();
      if (algorithm == cryptographic_algorithm::KMIP_CRYPTOALG_UNSET) {
        return "Cannot register a symmetric key without a Cryptographic "
               "Algorithm: raw key material does not carry it";
      }
      if (!algorithm_defined_in(algorithm, version)) {
        return "Cannot register a symmetric key with Cryptographic Algorithm " +
               std::to_string(static_cast<std::uint32_t>(algorithm)) +
               ", which KMIP " + std::to_string(version.getMajor()) + "." +
               std::to_string(version.getMinor()) + " does not define";
      }
      if (const auto length = key.attributes().crypto_length()) {
        return "Cannot register a symmetric key with Cryptographic Length " +
               std::to_string(*length) + ": it must be positive";
      }
      if (key.value().empty()) {
        return "Cannot register a symmetric key without a Cryptographic "
               "Length (an empty value and no length set)";
      }
      return "Cannot register a symmetric key of " +
             std::to_string(key.value().size()) +
             " bytes: its length in bits does not fit a Cryptographic Length";
    }

    std::shared_ptr<Element> make_key_object_from_key(
        const Key &key, const ProtocolVersion &version
    ) {
      const auto pair = algorithm_and_length(key, version);
      const std::optional<int32_t> key_alg =
          pair ? std::optional<int32_t>(pair->algorithm) : std::nullopt;
      const std::optional<int32_t> key_len =
          pair ? std::optional<int32_t>(pair->length) : std::nullopt;
      // The value's own Key Format Type when known (e.g. PKCS#1 for a key a
      // server only returned that way), else the default of its type.
      const auto format_or = [&](int32_t default_format) {
        return key.key_format().value_or(default_format);
      };
      switch (key.type()) {
        case KeyType::SYMMETRIC_KEY: {
          // Raw key material does not carry its algorithm, so a symmetric
          // Key Block must (KMIP 1.4 §2.1.3 Table 7, 2.0 §3.1).
          if (!pair) {
            throw KmipException(
                KMIP_INVALID_FIELD,
                symmetric_key_without_algorithm_and_length(key, version)
            );
          }
          auto symmetric_key =
              Element::createStructure(tag::KMIP_TAG_SYMMETRIC_KEY);
          symmetric_key->asStructure()->add(make_key_block(
              format_or(KMIP_KEYFORMAT_RAW), key.value(), key_alg, key_len
          ));
          return symmetric_key;
        }
        case KeyType::PRIVATE_KEY: {
          auto private_key =
              Element::createStructure(tag::KMIP_TAG_PRIVATE_KEY);
          private_key->asStructure()->add(make_key_block(
              format_or(KMIP_KEYFORMAT_PKCS8), key.value(), key_alg, key_len
          ));
          return private_key;
        }
        case KeyType::PUBLIC_KEY: {
          auto public_key = Element::createStructure(tag::KMIP_TAG_PUBLIC_KEY);
          public_key->asStructure()->add(make_key_block(
              format_or(KMIP_KEYFORMAT_X509), key.value(), key_alg, key_len
          ));
          return public_key;
        }
        case KeyType::CERTIFICATE:
          throw KmipException(
              KMIP_NOT_IMPLEMENTED,
              "Certificate registration is not yet supported"
          );
        case KeyType::UNSET:
        default:
          throw KmipException(
              KMIP_INVALID_FIELD, "Unsupported key type for Register"
          );
      }
    }
    int32_t object_type_from_key_type(KeyType key_type) {
      switch (key_type) {
        case KeyType::SYMMETRIC_KEY:
          return KMIP_OBJTYPE_SYMMETRIC_KEY;
        case KeyType::PRIVATE_KEY:
          return KMIP_OBJTYPE_PRIVATE_KEY;
        case KeyType::PUBLIC_KEY:
          return KMIP_OBJTYPE_PUBLIC_KEY;
        case KeyType::CERTIFICATE:
          return KMIP_OBJTYPE_CERTIFICATE;
        case KeyType::UNSET:
        default:
          throw KmipException(
              KMIP_INVALID_FIELD, "Unsupported key type for Register"
          );
      }
    }
    std::shared_ptr<Element>
        make_symmetric_key(std::span<const unsigned char> key_value) {
      auto symmetric_key =
          Element::createStructure(tag::KMIP_TAG_SYMMETRIC_KEY);
      symmetric_key->asStructure()->add(make_key_block(
          KMIP_KEYFORMAT_RAW,
          key_value,
          KMIP_CRYPTOALG_AES,
          static_cast<int32_t>(key_value.size() * 8)
      ));
      return symmetric_key;
    }
    std::shared_ptr<Element> make_secret_data(
        std::span<const unsigned char> secret, secret_data_type secret_type
    ) {
      auto secret_data = Element::createStructure(tag::KMIP_TAG_SECRET_DATA);
      secret_data->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_SECRET_DATA_TYPE, static_cast<int32_t>(secret_type)
          )
      );
      secret_data->asStructure()->add(make_key_block(
          KMIP_KEYFORMAT_OPAQUE, secret, std::nullopt, std::nullopt
      ));
      return secret_data;
    }
    std::shared_ptr<Element> make_attributes_container(
        const ProtocolVersion &version,
        const std::vector<std::shared_ptr<Element>> &attributes
    ) {
      if (use_attributes_container(version)) {
        auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
        for (const auto &attribute : attributes) {
          attrs->asStructure()->add(attribute);
        }
        return attrs;
      }
      return make_template_attribute(attributes);
    }

    // -------------------------------------------------------------------------
    // KMIP 2.0: helpers that build properly-typed child elements for the
    // Attributes container (no Attribute name/value wrappers).
    // -------------------------------------------------------------------------

    std::shared_ptr<Element> make_v2_name_struct(const std::string &value) {
      auto name = Element::createStructure(tag::KMIP_TAG_NAME);
      name->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_NAME_VALUE, value)
      );
      name->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_NAME_TYPE, KMIP_NAME_UNINTERPRETED_TEXT_STRING
          )
      );
      return name;
    }

    /**
     * @brief Builds an Attributes container (KMIP 2.0) for a symmetric-key
     *        Create request using properly typed child elements.
     */
    std::shared_ptr<Element> make_v2_create_symmetric_attrs(
        const std::string &name,
        const std::string &group,
        int32_t key_bits,
        cryptographic_usage_mask usage_mask
    ) {
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, KMIP_CRYPTOALG_AES
          )
      );
      attrs->asStructure()->add(
          Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, key_bits)
      );
      attrs->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK,
              static_cast<int32_t>(usage_mask)
          )
      );
      attrs->asStructure()->add(make_v2_name_struct(name));
      if (!group.empty()) {
        attrs->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, group)
        );
      }
      return attrs;
    }

    /**
     * @brief Builds an Attributes container (KMIP 2.0) for a Register
     *        (symmetric key) request.
     */
    std::shared_ptr<Element> make_v2_register_symmetric_attrs(
        const std::string &name,
        const std::string &group,
        int32_t key_bits,
        int32_t usage_mask_bits
    ) {
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, KMIP_CRYPTOALG_AES
          )
      );
      attrs->asStructure()->add(
          Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, key_bits)
      );
      attrs->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK, usage_mask_bits
          )
      );
      attrs->asStructure()->add(make_v2_name_struct(name));
      if (!group.empty()) {
        attrs->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, group)
        );
      }
      return attrs;
    }

    /**
     * @brief Builds an Attributes container (KMIP 2.0) for a Register
     *        (secret data) request.
     */
    std::shared_ptr<Element> make_v2_register_secret_attrs(
        const std::string &name, const std::string &group
    ) {
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK,
              KMIP_CRYPTOMASK_DERIVE_KEY | KMIP_CRYPTOMASK_EXPORT
          )
      );
      attrs->asStructure()->add(make_v2_name_struct(name));
      if (!group.empty()) {
        attrs->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, group)
        );
      }
      return attrs;
    }

    /**
     * @brief Builds an Attributes container (KMIP 2.0) for a generic Register
     *        (key) request from a Key object's typed and generic attributes.
     */
    std::shared_ptr<Element> make_v2_register_key_attrs(
        const std::string &name,
        const std::string &group,
        const Key &key,
        const ProtocolVersion &version
    ) {
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(make_v2_name_struct(name));
      if (!group.empty()) {
        attrs->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, group)
        );
      }
      if (const auto pair = algorithm_and_length(key, version)) {
        attrs->asStructure()->add(
            Element::createEnumeration(
                tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, pair->algorithm
            )
        );
        attrs->asStructure()->add(
            Element::createInteger(
                tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, pair->length
            )
        );
      }
      if (const auto mask = key.attributes().usage_mask();
          mask != cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET) {
        attrs->asStructure()->add(
            Element::createInteger(
                tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK,
                static_cast<int32_t>(mask)
            )
        );
      }
      // Generic attributes: not representable as typed KMIP 2.0 elements;
      // omit them to avoid protocol errors. Callers should use well-known
      // typed fields for all standard attributes.
      return attrs;
    }

  }  // namespace detail

  GetAttributesRequest::GetAttributesRequest(
      const std::string &unique_id,
      const std::vector<std::string> &attribute_names,
      ProtocolVersion version,
      bool legacy_attribute_names_for_v2
  ) {
    setOperation(KMIP_OP_GET_ATTRIBUTES);
    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, unique_id)
    );

    // Deduplicate selectors while preserving first-seen order.
    std::vector<std::string> unique_names;
    std::unordered_set<std::string> seen;
    unique_names.reserve(attribute_names.size());
    for (const auto &attr_name : attribute_names) {
      if (seen.insert(attr_name).second) {
        unique_names.push_back(attr_name);
      }
    }

    if (detail::use_attributes_container(version) &&
        !legacy_attribute_names_for_v2) {
      // KMIP 2.0: Get Attributes selectors are Attribute Reference structures.
      for (const auto &attr_name : unique_names) {
        payload->asStructure()->add(
            detail::make_v2_attribute_reference(attr_name)
        );
      }
    } else {
      // KMIP 1.x and compatibility fallback: selectors as Attribute Name text
      // strings.
      for (const auto &attr_name : unique_names) {
        payload->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, attr_name)
        );
      }
    }

    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // CreateSymmetricKeyRequest
  // ---------------------------------------------------------------------------
  CreateSymmetricKeyRequest::CreateSymmetricKeyRequest(
      const std::string &name,
      const std::string &group,
      int32_t key_bits,
      cryptographic_usage_mask usage_mask,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_CREATE);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SYMMETRIC_KEY
        )
    );

    if (detail::use_attributes_container(version)) {
      // KMIP 2.0: properly typed elements in Attributes container.
      payload->asStructure()->add(
          detail::make_v2_create_symmetric_attrs(
              name, group, key_bits, usage_mask
          )
      );
    } else {
      // KMIP 1.x: Attribute name/value pairs wrapped in TemplateAttribute.
      std::vector<std::shared_ptr<Element>> attributes;
      attributes.push_back(
          detail::make_enum_attribute(
              "Cryptographic Algorithm", KMIP_CRYPTOALG_AES
          )
      );
      attributes.push_back(
          detail::make_integer_attribute("Cryptographic Length", key_bits)
      );
      attributes.push_back(
          detail::make_integer_attribute(
              "Cryptographic Usage Mask", static_cast<int32_t>(usage_mask)
          )
      );
      attributes.push_back(detail::make_name_attribute(name));
      if (!group.empty()) {
        attributes.push_back(
            detail::make_text_attribute("Object Group", group)
        );
      }
      payload->asStructure()->add(detail::make_template_attribute(attributes));
    }

    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // RegisterSymmetricKeyRequest
  // ---------------------------------------------------------------------------
  RegisterSymmetricKeyRequest::RegisterSymmetricKeyRequest(
      const std::string &name,
      const std::string &group,
      std::span<const unsigned char> key_value,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_REGISTER);

    const int32_t key_bits = static_cast<int32_t>(key_value.size() * 8);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SYMMETRIC_KEY
        )
    );

    if (detail::use_attributes_container(version)) {
      payload->asStructure()->add(
          detail::make_v2_register_symmetric_attrs(
              name,
              group,
              key_bits,
              KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT
          )
      );
    } else {
      std::vector<std::shared_ptr<Element>> attributes;
      attributes.push_back(
          detail::make_enum_attribute(
              "Cryptographic Algorithm", KMIP_CRYPTOALG_AES
          )
      );
      attributes.push_back(
          detail::make_integer_attribute("Cryptographic Length", key_bits)
      );
      attributes.push_back(
          detail::make_integer_attribute(
              "Cryptographic Usage Mask",
              KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT
          )
      );
      attributes.push_back(detail::make_name_attribute(name));
      if (!group.empty()) {
        attributes.push_back(
            detail::make_text_attribute("Object Group", group)
        );
      }
      payload->asStructure()->add(detail::make_template_attribute(attributes));
    }

    payload->asStructure()->add(detail::make_symmetric_key(key_value));
    setRequestPayload(payload);
  }

  RegisterKeyRequest::RegisterKeyRequest(
      const std::string &name,
      const std::string &group,
      const Key &key,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_REGISTER);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_OBJECT_TYPE,
            detail::object_type_from_key_type(key.type())
        )
    );

    if (detail::use_attributes_container(version)) {
      // KMIP 2.0: properly typed elements in Attributes container.
      payload->asStructure()->add(
          detail::make_v2_register_key_attrs(name, group, key, version)
      );
    } else {
      // KMIP 1.x: Attribute name/value pairs in TemplateAttribute.
      std::vector<std::shared_ptr<Element>> attributes;
      attributes.push_back(detail::make_name_attribute(name));
      if (!group.empty()) {
        attributes.push_back(
            detail::make_text_attribute("Object Group", group)
        );
      }

      if (const auto pair = detail::algorithm_and_length(key, version)) {
        attributes.push_back(
            detail::make_enum_attribute(
                "Cryptographic Algorithm", pair->algorithm
            )
        );
        attributes.push_back(
            detail::make_integer_attribute("Cryptographic Length", pair->length)
        );
      }
      if (const auto mask = key.attributes().usage_mask();
          mask != cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET) {
        attributes.push_back(
            detail::make_integer_attribute(
                "Cryptographic Usage Mask", static_cast<int32_t>(mask)
            )
        );
      }

      for (const auto &[attr_name, attr_val] : key.attributes().generic()) {
        if (attr_name == "Name" || attr_name == "Object Group") {
          continue;
        }
        std::string str_val = std::visit(
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
            attr_val
        );
        attributes.push_back(detail::make_text_attribute(attr_name, str_val));
      }
      payload->asStructure()->add(detail::make_template_attribute(attributes));
    }

    payload->asStructure()->add(detail::make_key_object_from_key(key, version));
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // RegisterSecretRequest
  // ---------------------------------------------------------------------------
  RegisterSecretRequest::RegisterSecretRequest(
      const std::string &name,
      const std::string &group,
      std::span<const unsigned char> secret,
      secret_data_type secret_type,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_REGISTER);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SECRET_DATA
        )
    );

    if (detail::use_attributes_container(version)) {
      payload->asStructure()->add(
          detail::make_v2_register_secret_attrs(name, group)
      );
    } else {
      std::vector<std::shared_ptr<Element>> attributes;
      attributes.push_back(
          detail::make_integer_attribute(
              "Cryptographic Usage Mask",
              KMIP_CRYPTOMASK_DERIVE_KEY | KMIP_CRYPTOMASK_EXPORT
          )
      );
      attributes.push_back(detail::make_name_attribute(name));
      if (!group.empty()) {
        attributes.push_back(
            detail::make_text_attribute("Object Group", group)
        );
      }
      payload->asStructure()->add(detail::make_template_attribute(attributes));
    }

    payload->asStructure()->add(detail::make_secret_data(secret, secret_type));
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // LocateRequest
  // ---------------------------------------------------------------------------
  LocateRequest::LocateRequest(
      bool locate_by_group,
      const std::string &name,
      object_type obj_type,
      size_t max_items,
      size_t offset,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_LOCATE);

    constexpr auto int32_max =
        static_cast<size_t>(std::numeric_limits<int32_t>::max());
    if (max_items > int32_max) {
      throw KmipException(
          "LocateRequest: max_items value " + std::to_string(max_items) +
          " exceeds int32_t maximum (" + std::to_string(int32_max) + ")"
      );
    }
    if (offset > int32_max) {
      throw KmipException(
          "LocateRequest: offset value " + std::to_string(offset) +
          " exceeds int32_t maximum (" + std::to_string(int32_max) + ")"
      );
    }

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    if (max_items > 0) {
      payload->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_MAXIMUM_ITEMS, static_cast<int32_t>(max_items)
          )
      );
    }
    if (offset > 0) {
      payload->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_OFFSET_ITEMS, static_cast<int32_t>(offset)
          )
      );
    }

    if (detail::use_attributes_container(version)) {
      // KMIP 2.0: filter attributes go into an Attributes container with
      // properly typed child elements.
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_OBJECT_TYPE, static_cast<int32_t>(obj_type)
          )
      );
      if (!name.empty()) {
        if (locate_by_group) {
          attrs->asStructure()->add(
              Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, name)
          );
        } else {
          attrs->asStructure()->add(detail::make_v2_name_struct(name));
        }
      }
      payload->asStructure()->add(attrs);
    } else {
      // KMIP 1.x: individual Attribute structures directly in payload.
      payload->asStructure()->add(
          detail::make_enum_attribute(
              "Object Type", static_cast<int32_t>(obj_type)
          )
      );
      if (!name.empty()) {
        if (locate_by_group) {
          payload->asStructure()->add(
              detail::make_text_attribute("Object Group", name)
          );
        } else {
          payload->asStructure()->add(detail::make_name_attribute(name));
        }
      }
    }
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // RevokeRequest
  // ---------------------------------------------------------------------------
  RevokeRequest::RevokeRequest(
      const std::string &unique_id,
      revocation_reason_type reason,
      const std::string &message,
      time_t occurrence_time
  ) {
    setOperation(KMIP_OP_REVOKE);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, unique_id)
    );

    auto revocation_reason =
        Element::createStructure(tag::KMIP_TAG_REVOCATION_REASON);
    revocation_reason->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_REVOCATION_REASON_CODE, static_cast<int32_t>(reason)
        )
    );
    if (!message.empty()) {
      revocation_reason->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_REVOKATION_MESSAGE, message)
      );
    }
    payload->asStructure()->add(revocation_reason);

    if (occurrence_time > 0) {
      payload->asStructure()->add(
          Element::createDateTime(
              tag::KMIP_TAG_COMPROMISE_OCCURRANCE_DATE,
              static_cast<int64_t>(occurrence_time)
          )
      );
    }
    setRequestPayload(payload);
  }

}  // namespace kmipcore
