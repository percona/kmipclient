/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_KMIP_RESPONSES_HPP
#define KMIPCORE_KMIP_RESPONSES_HPP

#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/kmip_protocol.hpp"

#include <optional>
#include <string>

namespace kmipcore {

  namespace detail {
    /** @brief Validates response operation code against expected value. */
    inline void expect_operation(
        const ResponseBatchItem &item,
        int32_t expectedOperation,
        const char *className
    ) {
      if (item.getOperation() != expectedOperation) {
        throw KmipException(
            std::string(className) +
            ": unexpected operation in response batch item"
        );
      }
    }

    /** @brief Returns response payload or throws when it is missing. */
    inline std::shared_ptr<Element> require_response_payload(
        const ResponseBatchItem &item, const char *className
    ) {
      auto payload = item.getResponsePayload();
      if (!payload) {
        throw KmipException(
            std::string(className) + ": missing response payload"
        );
      }
      return payload;
    }
  }  // namespace detail

  // ---------------------------------------------------------------------------
  // CRTP Base class to reduce boilerplate for fromElement and constructors.
  // ---------------------------------------------------------------------------
  template<typename Derived>
  class BaseResponseBatchItem : public ResponseBatchItem {
  public:
    using ResponseBatchItem::ResponseBatchItem;

    /** @brief Constructs typed wrapper from plain response batch item. */
    explicit BaseResponseBatchItem(const ResponseBatchItem &other)
      : ResponseBatchItem(other) {}

    /** @brief Decodes typed wrapper directly from TTLV element form. */
    static Derived fromElement(std::shared_ptr<Element> element) {
      return Derived::fromBatchItem(
          ResponseBatchItem::fromElement(std::move(element))
      );
    }
  };

  // ---------------------------------------------------------------------------
  // Common base template for simple response batch items that only carry a
  // unique-identifier extracted from the response payload.
  // OpCode is the expected KMIP operation enum value (e.g. KMIP_OP_CREATE).
  // ---------------------------------------------------------------------------
  template<int32_t OpCode>
  class SimpleIdResponseBatchItem
    : public BaseResponseBatchItem<SimpleIdResponseBatchItem<OpCode>> {
  public:
    using Base = BaseResponseBatchItem<SimpleIdResponseBatchItem<OpCode>>;
    using Base::Base;  // Inherit constructors

    /** @brief Converts generic response item into typed simple-id response. */
    static SimpleIdResponseBatchItem
        fromBatchItem(const ResponseBatchItem &item) {
      detail::expect_operation(item, OpCode, "SimpleIdResponseBatchItem");

      SimpleIdResponseBatchItem result(item);
      auto payload =
          detail::require_response_payload(item, "SimpleIdResponseBatchItem");

      auto uid = payload->getChild(tag::KMIP_TAG_UNIQUE_IDENTIFIER);
      if (!uid) {
        throw KmipException(
            "SimpleIdResponseBatchItem: missing unique identifier in response "
            "payload"
        );
      }
      result.uniqueIdentifier_ = uid->toString();
      return result;
    }

    /** @brief Returns response unique identifier field. */
    [[nodiscard]] const std::string &getUniqueIdentifier() const {
      return uniqueIdentifier_;
    }

  private:
    std::string uniqueIdentifier_;
  };

  /** @brief Typed response alias for KMIP Create operation. */
  using CreateResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_CREATE>;
  /** @brief Typed response alias for KMIP Register operation. */
  using RegisterResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_REGISTER>;
  /** @brief Typed response alias for KMIP Activate operation. */
  using ActivateResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_ACTIVATE>;
  /** @brief Typed response alias for KMIP Revoke operation. */
  using RevokeResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_REVOKE>;
  /** @brief Typed response alias for KMIP Destroy operation. */
  using DestroyResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_DESTROY>;

  // ---------------------------------------------------------------------------
  // Response types with additional fields beyond unique-identifier.
  // ---------------------------------------------------------------------------

  /** @brief Typed response for KMIP Get operation. */
  class GetResponseBatchItem
    : public BaseResponseBatchItem<GetResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Get response view. */
    static GetResponseBatchItem fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns unique identifier from response payload. */
    [[nodiscard]] const std::string &getUniqueIdentifier() const {
      return uniqueIdentifier_;
    }
    /** @brief Returns KMIP object_type value from response payload. */
    [[nodiscard]] int32_t getObjectType() const { return objectType_; }
    /** @brief Returns element containing the returned KMIP object content. */
    [[nodiscard]] std::shared_ptr<Element> getObjectElement() const {
      return objectElement_;
    }

  private:
    std::string uniqueIdentifier_;
    int32_t objectType_ = 0;
    std::shared_ptr<Element> objectElement_;
  };

  /** @brief Typed response for KMIP Get Attributes operation. */
  class GetAttributesResponseBatchItem
    : public BaseResponseBatchItem<GetAttributesResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Get Attributes response. */
    static GetAttributesResponseBatchItem
        fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns raw attribute elements carried by the payload. */
    [[nodiscard]] const std::vector<std::shared_ptr<Element>> &
        getAttributes() const {
      return attributes_;
    }

    /**
     * @brief Returns the Unique Identifier of the object the attributes
     *        belong to, when the payload has one (REQUIRED by KMIP 1.4
     *        Table 197 and 2.0 Table 209, but not enforced here).
     */
    [[nodiscard]] const std::optional<std::string> &
        getUniqueIdentifier() const {
      return uniqueIdentifier_;
    }

  private:
    std::vector<std::shared_ptr<Element>> attributes_;
    std::optional<std::string> uniqueIdentifier_;
  };

  /** @brief Typed response for KMIP Get Attribute List operation. */
  class GetAttributeListResponseBatchItem
    : public BaseResponseBatchItem<GetAttributeListResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Get Attribute List response.
     */
    static GetAttributeListResponseBatchItem
        fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns attribute names present in the target object. */
    [[nodiscard]] const std::vector<std::string> &getAttributeNames() const {
      return attributeNames_;
    }

  private:
    std::vector<std::string> attributeNames_;
  };

  /** @brief Typed response for KMIP Locate operation. */
  class LocateResponseBatchItem
    : public BaseResponseBatchItem<LocateResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Locate response view. */
    static LocateResponseBatchItem fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns parsed locate payload metadata and identifiers. */
    [[nodiscard]] const LocateResponsePayload &getLocatePayload() const {
      return locatePayload_;
    }
    /** @brief Returns located unique identifiers from payload. */
    [[nodiscard]] const std::vector<std::string> &getUniqueIdentifiers() const {
      return locatePayload_.getUniqueIdentifiers();
    }

  private:
    LocateResponsePayload locatePayload_;
  };

  /**
   * @brief Typed response for KMIP Discover Versions operation (KMIP 1.1+).
   *
   * The response payload contains zero or more ProtocolVersion structures
   * listing all versions supported by the server.
   */
  class DiscoverVersionsResponseBatchItem
    : public BaseResponseBatchItem<DiscoverVersionsResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Discover Versions response.
     */
    static DiscoverVersionsResponseBatchItem
        fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns the list of protocol versions advertised by the server.
     */
    [[nodiscard]] const std::vector<ProtocolVersion> &
        getProtocolVersions() const {
      return protocolVersions_;
    }

  private:
    std::vector<ProtocolVersion> protocolVersions_;
  };

  /** @brief Typed response for KMIP Query operation. */
  class QueryResponseBatchItem
    : public BaseResponseBatchItem<QueryResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Query response view. */
    static QueryResponseBatchItem fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns operation codes supported by the server. */
    [[nodiscard]] const std::vector<int32_t> &getOperations() const {
      return operations_;
    }
    /** @brief Returns object types supported by the server. */
    [[nodiscard]] const std::vector<int32_t> &getObjectTypes() const {
      return objectTypes_;
    }
    /** @brief Returns vendor identification returned by the server. */
    [[nodiscard]] const std::string &getVendorIdentification() const {
      return vendorIdentification_;
    }
    /** @brief Returns server name returned by the server. */
    [[nodiscard]] const std::string &getServerName() const {
      return serverName_;
    }
    /** @brief Returns product name returned by the server. */
    [[nodiscard]] const std::string &getProductName() const {
      return productName_;
    }
    /** @brief Returns server version returned by the server. */
    [[nodiscard]] const std::string &getServerVersion() const {
      return serverVersion_;
    }
    /** @brief Returns build level returned by the server. */
    [[nodiscard]] const std::string &getBuildLevel() const {
      return buildLevel_;
    }
    /** @brief Returns build date returned by the server. */
    [[nodiscard]] const std::string &getBuildDate() const { return buildDate_; }
    /** @brief Returns server serial number returned by the server. */
    [[nodiscard]] const std::string &getServerSerialNumber() const {
      return serverSerialNumber_;
    }
    /** @brief Returns server load returned by the server. */
    [[nodiscard]] const std::string &getServerLoad() const {
      return serverLoad_;
    }
    /** @brief Returns cluster information returned by the server. */
    [[nodiscard]] const std::string &getClusterInfo() const {
      return clusterInfo_;
    }

  private:
    std::vector<int32_t> operations_;
    std::vector<int32_t> objectTypes_;
    std::string vendorIdentification_;
    std::string serverName_;
    std::string productName_;
    std::string serverVersion_;
    std::string buildLevel_;
    std::string buildDate_;
    std::string serverSerialNumber_;
    std::string serverLoad_;
    std::string clusterInfo_;
  };

}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_RESPONSES_HPP */
