/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/kmip_responses.hpp"

#include "kmipcore/kmip_attribute_names.hpp"
#include "kmipcore/kmip_errors.hpp"

namespace kmipcore {

  namespace {

    std::shared_ptr<Element> get_object_element_for_type(
        const std::shared_ptr<Element> &payload, int32_t objectType
    ) {
      switch (objectType) {
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
          return payload->getChild(tag::KMIP_TAG_SYMMETRIC_KEY);
        case KMIP_OBJTYPE_SECRET_DATA:
          return payload->getChild(tag::KMIP_TAG_SECRET_DATA);
        case KMIP_OBJTYPE_PRIVATE_KEY:
          return payload->getChild(tag::KMIP_TAG_PRIVATE_KEY);
        case KMIP_OBJTYPE_PUBLIC_KEY:
          return payload->getChild(tag::KMIP_TAG_PUBLIC_KEY);
        default:
          return {};
      }
    }

    [[nodiscard]] std::optional<std::string>
        attribute_name_from_tag_code(int32_t tag_code) {
      switch (static_cast<Tag>(tag_code)) {
        case tag::KMIP_TAG_NAME:
          return std::string(KMIP_ATTR_NAME_NAME);
        case tag::KMIP_TAG_OBJECT_GROUP:
          return std::string(KMIP_ATTR_NAME_GROUP);
        case tag::KMIP_TAG_STATE:
          return std::string(KMIP_ATTR_NAME_STATE);
        case tag::KMIP_TAG_UNIQUE_IDENTIFIER:
          return std::string(KMIP_ATTR_NAME_UNIQUE_IDENTIFIER);
        case tag::KMIP_TAG_ACTIVATION_DATE:
          return std::string(KMIP_ATTR_NAME_ACTIVATION_DATE);
        case tag::KMIP_TAG_DEACTIVATION_DATE:
          return std::string(KMIP_ATTR_NAME_DEACTIVATION_DATE);
        case tag::KMIP_TAG_PROCESS_START_DATE:
          return std::string(KMIP_ATTR_NAME_PROCESS_START_DATE);
        case tag::KMIP_TAG_PROTECT_STOP_DATE:
          return std::string(KMIP_ATTR_NAME_PROTECT_STOP_DATE);
        case tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
          return std::string(KMIP_ATTR_NAME_CRYPTO_ALG);
        case tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH:
          return std::string(KMIP_ATTR_NAME_CRYPTO_LEN);
        case tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK:
          return std::string(KMIP_ATTR_NAME_CRYPTO_USAGE_MASK);
        case tag::KMIP_TAG_OPERATION_POLICY_NAME:
          return std::string(KMIP_ATTR_NAME_OPERATION_POLICY_NAME);
        default:
          return std::nullopt;
      }
    }

    void collect_attribute_list_entries_from_reference(
        const std::shared_ptr<Element> &attribute_reference,
        std::vector<std::string> &out_names
    ) {
      if (!attribute_reference) {
        return;
      }

      if (attribute_reference->type == Type::KMIP_TYPE_ENUMERATION) {
        if (const auto mapped =
                attribute_name_from_tag_code(attribute_reference->toEnum());
            mapped.has_value()) {
          out_names.push_back(*mapped);
        }
        return;
      }

      if (attribute_reference->type != Type::KMIP_TYPE_STRUCTURE) {
        return;
      }

      if (const auto attr_name =
              attribute_reference->getChild(tag::KMIP_TAG_ATTRIBUTE_NAME);
          attr_name) {
        out_names.push_back(attr_name->toString());
        return;
      }

      if (const auto attr_tag =
              attribute_reference->getChild(tag::KMIP_TAG_ATTRIBUTE_REFERENCE);
          attr_tag) {
        if (const auto mapped =
                attribute_name_from_tag_code(attr_tag->toEnum());
            mapped.has_value()) {
          out_names.push_back(*mapped);
        }
      }
    }

  }  // namespace

  // --- GetResponseBatchItem ---

  GetResponseBatchItem
      GetResponseBatchItem::fromBatchItem(const ResponseBatchItem &item) {
    detail::expect_operation(item, KMIP_OP_GET, "GetResponseBatchItem");

    GetResponseBatchItem result(item);

    auto payload =
        detail::require_response_payload(item, "GetResponseBatchItem");

    auto uniqueIdentifier = payload->getChild(tag::KMIP_TAG_UNIQUE_IDENTIFIER);
    if (!uniqueIdentifier) {
      throw KmipException(
          "GetResponseBatchItem: missing unique identifier in response payload"
      );
    }
    if (uniqueIdentifier->type != Type::KMIP_TYPE_TEXT_STRING) {
      throw KmipException(
          KMIP_INVALID_ENCODING,
          "GetResponseBatchItem: Unique Identifier is not a Text String"
      );
    }
    result.uniqueIdentifier_ = uniqueIdentifier->toString();

    auto objectType = payload->getChild(tag::KMIP_TAG_OBJECT_TYPE);
    if (!objectType) {
      throw KmipException(
          "GetResponseBatchItem: missing object type in response payload"
      );
    }

    result.objectType_ = objectType->toEnum();
    result.objectElement_ =
        get_object_element_for_type(payload, result.objectType_);
    if (!result.objectElement_) {
      throw KmipException(
          "GetResponseBatchItem: missing object payload for object type"
      );
    }

    return result;
  }

  // --- GetAttributesResponseBatchItem ---

  GetAttributesResponseBatchItem GetAttributesResponseBatchItem::fromBatchItem(
      const ResponseBatchItem &item
  ) {
    detail::expect_operation(
        item, KMIP_OP_GET_ATTRIBUTES, "GetAttributesResponseBatchItem"
    );

    GetAttributesResponseBatchItem result(item);
    auto payload = detail::require_response_payload(
        item, "GetAttributesResponseBatchItem"
    );
    // A Text String in responses (KMIP 1.4 §3.1, 2.0 §4.51: the other
    // forms exist only in requests).
    if (const auto id = payload->getChild(tag::KMIP_TAG_UNIQUE_IDENTIFIER)) {
      if (id->type != Type::KMIP_TYPE_TEXT_STRING) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            "GetAttributesResponseBatchItem: Unique Identifier is not a Text "
            "String"
        );
      }
      result.uniqueIdentifier_ = id->toString();
    }

    // KMIP 1.x returns Attribute elements directly under Response Payload.
    // KMIP 2.0 wraps attributes inside an Attributes structure with typed
    // children.
    result.attributes_ = payload->getChildren(tag::KMIP_TAG_ATTRIBUTE);
    if (result.attributes_.empty()) {
      if (const auto attributes = payload->getChild(tag::KMIP_TAG_ATTRIBUTES);
          attributes) {
        // Try transitional style (Attribute wrappers inside Attributes
        // container).
        result.attributes_ = attributes->getChildren(tag::KMIP_TAG_ATTRIBUTE);
        if (result.attributes_.empty() && attributes->asStructure()) {
          // Pure KMIP 2.0: typed elements (e.g.
          // KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM) directly inside the Attributes
          // container.
          result.attributes_ = attributes->asStructure()->items;
        }
      }
    }
    return result;
  }

  // --- GetAttributeListResponseBatchItem ---

  GetAttributeListResponseBatchItem
      GetAttributeListResponseBatchItem::fromBatchItem(
          const ResponseBatchItem &item
      ) {
    detail::expect_operation(
        item, KMIP_OP_GET_ATTRIBUTE_LIST, "GetAttributeListResponseBatchItem"
    );

    GetAttributeListResponseBatchItem result(item);
    auto payload = detail::require_response_payload(
        item, "GetAttributeListResponseBatchItem"
    );

    for (const auto &attributeName :
         payload->getChildren(tag::KMIP_TAG_ATTRIBUTE_NAME)) {
      result.attributeNames_.push_back(attributeName->toString());
    }

    if (result.attributeNames_.empty()) {
      // KMIP 2.0: Get Attribute List returns Attribute Reference values.
      for (const auto &attributeReference :
           payload->getChildren(tag::KMIP_TAG_ATTRIBUTE_REFERENCE)) {
        collect_attribute_list_entries_from_reference(
            attributeReference, result.attributeNames_
        );
      }
    }

    return result;
  }

  // --- LocateResponseBatchItem ---

  LocateResponseBatchItem
      LocateResponseBatchItem::fromBatchItem(const ResponseBatchItem &item) {
    detail::expect_operation(item, KMIP_OP_LOCATE, "LocateResponseBatchItem");

    LocateResponseBatchItem result(item);
    result.locatePayload_ = LocateResponsePayload::fromElement(
        detail::require_response_payload(item, "LocateResponseBatchItem")
    );
    return result;
  }

  // --- DiscoverVersionsResponseBatchItem ---

  DiscoverVersionsResponseBatchItem
      DiscoverVersionsResponseBatchItem::fromBatchItem(
          const ResponseBatchItem &item
      ) {
    detail::expect_operation(
        item, KMIP_OP_DISCOVER_VERSIONS, "DiscoverVersionsResponseBatchItem"
    );

    DiscoverVersionsResponseBatchItem result(item);

    // The response payload is optional: the server may return no payload at all
    // when it supports no versions other than the negotiated one, or when the
    // request contained a version list the server couldn't match.
    auto payload = item.getResponsePayload();
    if (payload) {
      for (const auto &pvElement :
           payload->getChildren(tag::KMIP_TAG_PROTOCOL_VERSION)) {
        result.protocolVersions_.push_back(
            ProtocolVersion::fromElement(pvElement)
        );
      }
    }

    return result;
  }

  // --- QueryResponseBatchItem ---

  QueryResponseBatchItem
      QueryResponseBatchItem::fromBatchItem(const ResponseBatchItem &item) {
    detail::expect_operation(item, KMIP_OP_QUERY, "QueryResponseBatchItem");

    QueryResponseBatchItem result(item);

    // Query response payload is optional; an empty payload means no values.
    auto payload = item.getResponsePayload();
    if (!payload) {
      return result;
    }

    for (const auto &opElement :
         payload->getChildren(tag::KMIP_TAG_OPERATION)) {
      result.operations_.push_back(opElement->toEnum());
    }
    for (const auto &objElement :
         payload->getChildren(tag::KMIP_TAG_OBJECT_TYPE)) {
      result.objectTypes_.push_back(objElement->toEnum());
    }

    if (const auto vendor =
            payload->getChild(tag::KMIP_TAG_VENDOR_IDENTIFICATION);
        vendor) {
      result.vendorIdentification_ = vendor->toString();
    }

    if (const auto serverInfo =
            payload->getChild(tag::KMIP_TAG_SERVER_INFORMATION);
        serverInfo && serverInfo->asStructure()) {
      if (const auto serverName =
              serverInfo->getChild(tag::KMIP_TAG_SERVER_NAME);
          serverName) {
        result.serverName_ = serverName->toString();
      }
      if (const auto serial =
              serverInfo->getChild(tag::KMIP_TAG_SERVER_SERIAL_NUMBER);
          serial) {
        result.serverSerialNumber_ = serial->toString();
      }
      if (const auto version =
              serverInfo->getChild(tag::KMIP_TAG_SERVER_VERSION);
          version) {
        result.serverVersion_ = version->toString();
      }
      if (const auto load = serverInfo->getChild(tag::KMIP_TAG_SERVER_LOAD);
          load) {
        result.serverLoad_ = load->toString();
      }
      if (const auto product = serverInfo->getChild(tag::KMIP_TAG_PRODUCT_NAME);
          product) {
        result.productName_ = product->toString();
      }
      if (const auto buildLevel =
              serverInfo->getChild(tag::KMIP_TAG_BUILD_LEVEL);
          buildLevel) {
        result.buildLevel_ = buildLevel->toString();
      }
      if (const auto buildDate = serverInfo->getChild(tag::KMIP_TAG_BUILD_DATE);
          buildDate) {
        result.buildDate_ = buildDate->toString();
      }
      if (const auto clusterInfo =
              serverInfo->getChild(tag::KMIP_TAG_CLUSTER_INFO);
          clusterInfo) {
        result.clusterInfo_ = clusterInfo->toString();
      }
    }

    return result;
  }

}  // namespace kmipcore
