/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/kmip_protocol.hpp"

#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <cstring>
#include <ctime>
#include <limits>
#include <span>
#include <vector>

namespace kmipcore {

  namespace {

    [[nodiscard]] bool
        supports_date_time_extended(const ProtocolVersion &version) {
      return version.is_at_least(2, 0);
    }

    void validate_element_types_for_version(
        const std::shared_ptr<Element> &element, const ProtocolVersion &version
    ) {
      if (!element) {
        return;
      }

      if (element->type == Type::KMIP_TYPE_DATE_TIME_EXTENDED &&
          !supports_date_time_extended(version)) {
        throw KmipException("DateTimeExtended requires KMIP 2.0 or later");
      }

      if (const auto *structure = element->asStructure();
          structure != nullptr) {
        for (const auto &child : structure->items) {
          validate_element_types_for_version(child, version);
        }
      }
    }

    [[nodiscard]] std::vector<std::uint8_t>
        encode_batch_item_id(std::uint32_t id) {
      return {
          static_cast<std::uint8_t>((id >> 24) & 0xFF),
          static_cast<std::uint8_t>((id >> 16) & 0xFF),
          static_cast<std::uint8_t>((id >> 8) & 0xFF),
          static_cast<std::uint8_t>(id & 0xFF)
      };
    }

    [[nodiscard]] bool decode_batch_item_id(
        std::span<const std::uint8_t> encoded, std::uint32_t &decoded
    ) {
      if (encoded.empty() || encoded.size() > sizeof(decoded)) {
        return false;
      }

      decoded = 0;
      for (const auto byte : encoded) {
        decoded = (decoded << 8) | static_cast<std::uint32_t>(byte);
      }
      return true;
    }

  }  // namespace

  // === ProtocolVersion ===
  std::shared_ptr<Element> ProtocolVersion::toElement() const {
    auto structure = Element::createStructure(tag::KMIP_TAG_PROTOCOL_VERSION);
    structure->asStructure()->add(
        Element::createInteger(tag::KMIP_TAG_PROTOCOL_VERSION_MAJOR, major_)
    );
    structure->asStructure()->add(
        Element::createInteger(tag::KMIP_TAG_PROTOCOL_VERSION_MINOR, minor_)
    );
    return structure;
  }
  ProtocolVersion
      ProtocolVersion::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != tag::KMIP_TAG_PROTOCOL_VERSION ||
        element->type != Type::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid ProtocolVersion element");
    }
    ProtocolVersion pv;
    auto maj = element->getChild(tag::KMIP_TAG_PROTOCOL_VERSION_MAJOR);
    if (maj) {
      pv.major_ = maj->toInt();
    }
    auto min = element->getChild(tag::KMIP_TAG_PROTOCOL_VERSION_MINOR);
    if (min) {
      pv.minor_ = min->toInt();
    }
    return pv;
  }
  // === RequestHeader ===
  std::shared_ptr<Element> RequestHeader::toElement() const {
    auto structure = Element::createStructure(tag::KMIP_TAG_REQUEST_HEADER);
    structure->asStructure()->add(protocolVersion_.toElement());
    if (maximumResponseSize_) {
      structure->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_MAXIMUM_RESPONSE_SIZE, *maximumResponseSize_
          )
      );
    }
    if (batchOrderOption_) {
      structure->asStructure()->add(
          Element::createBoolean(
              tag::KMIP_TAG_BATCH_ORDER_OPTION, *batchOrderOption_
          )
      );
    }
    if (timeStamp_) {
      structure->asStructure()->add(
          Element::createDateTime(tag::KMIP_TAG_TIME_STAMP, *timeStamp_)
      );
    }
    if (userName_ || password_) {
      auto authentication =
          Element::createStructure(tag::KMIP_TAG_AUTHENTICATION);
      auto credential = Element::createStructure(tag::KMIP_TAG_CREDENTIAL);
      credential->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_CREDENTIAL_TYPE, KMIP_CRED_USERNAME_AND_PASSWORD
          )
      );

      auto credential_value =
          Element::createStructure(tag::KMIP_TAG_CREDENTIAL_VALUE);
      if (userName_) {
        credential_value->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_USERNAME, *userName_)
        );
      }
      if (password_) {
        credential_value->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_PASSWORD, *password_)
        );
      }

      credential->asStructure()->add(credential_value);
      authentication->asStructure()->add(credential);
      structure->asStructure()->add(authentication);
    }
    structure->asStructure()->add(
        Element::createInteger(tag::KMIP_TAG_BATCH_COUNT, batchCount_)
    );
    return structure;
  }
  RequestHeader RequestHeader::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != tag::KMIP_TAG_REQUEST_HEADER ||
        element->type != Type::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid RequestHeader element");
    }
    RequestHeader rh;
    auto pv = element->getChild(tag::KMIP_TAG_PROTOCOL_VERSION);
    if (pv) {
      rh.protocolVersion_ = ProtocolVersion::fromElement(pv);
    } else {
      throw KmipException("Missing ProtocolVersion in header");
    }
    auto maxResponseSize =
        element->getChild(tag::KMIP_TAG_MAXIMUM_RESPONSE_SIZE);
    if (maxResponseSize) {
      rh.maximumResponseSize_ = maxResponseSize->toInt();
    }
    auto timeStamp = element->getChild(tag::KMIP_TAG_TIME_STAMP);
    if (timeStamp) {
      rh.timeStamp_ = timeStamp->toLong();
    }
    auto batchOrderOption = element->getChild(tag::KMIP_TAG_BATCH_ORDER_OPTION);
    if (batchOrderOption) {
      rh.batchOrderOption_ = batchOrderOption->toBool();
    }
    auto authentication = element->getChild(tag::KMIP_TAG_AUTHENTICATION);
    if (authentication) {
      auto credential = authentication->getChild(tag::KMIP_TAG_CREDENTIAL);
      if (!credential) {
        throw KmipException("Missing Credential in Authentication");
      }

      auto credentialType = credential->getChild(tag::KMIP_TAG_CREDENTIAL_TYPE);
      auto credentialValue =
          credential->getChild(tag::KMIP_TAG_CREDENTIAL_VALUE);
      if (!credentialType || !credentialValue) {
        throw KmipException("Invalid Credential in Authentication");
      }

      if (credentialType->toEnum() == KMIP_CRED_USERNAME_AND_PASSWORD) {
        auto userName = credentialValue->getChild(tag::KMIP_TAG_USERNAME);
        if (userName) {
          rh.userName_ = userName->toString();
        }

        auto password = credentialValue->getChild(tag::KMIP_TAG_PASSWORD);
        if (password) {
          const auto pw = password->stringView();
          rh.password_.emplace(pw.begin(), pw.end());
        }
      }
    }
    auto bc = element->getChild(tag::KMIP_TAG_BATCH_COUNT);
    if (bc) {
      rh.batchCount_ = bc->toInt();
    }
    return rh;
  }
  // === RequestBatchItem ===
  std::shared_ptr<Element> RequestBatchItem::toElement() const {
    auto structure = Element::createStructure(tag::KMIP_TAG_BATCH_ITEM);
    structure->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_OPERATION, operation_)
    );
    if (uniqueBatchItemId_ != 0) {
      structure->asStructure()->add(
          Element::createByteString(
              tag::KMIP_TAG_UNIQUE_BATCH_ITEM_ID,
              encode_batch_item_id(uniqueBatchItemId_)
          )
      );
    }
    if (requestPayload_) {
      structure->asStructure()->add(requestPayload_);
    }
    return structure;
  }
  RequestBatchItem
      RequestBatchItem::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != tag::KMIP_TAG_BATCH_ITEM ||
        element->type != Type::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid RequestBatchItem element");
    }
    RequestBatchItem rbi;
    auto op = element->getChild(tag::KMIP_TAG_OPERATION);
    if (op) {
      rbi.operation_ = op->toEnum();
    } else {
      throw KmipException("Missing Operation");
    }
    auto id = element->getChild(tag::KMIP_TAG_UNIQUE_BATCH_ITEM_ID);
    if (id) {
      auto bytes = id->toBytes();
      std::uint32_t decoded_id = 0;
      if (decode_batch_item_id(bytes, decoded_id)) {
        rbi.uniqueBatchItemId_ = decoded_id;
      }
    }
    auto payload = element->getChild(tag::KMIP_TAG_REQUEST_PAYLOAD);
    if (payload) {
      rbi.requestPayload_ = payload;
    }
    return rbi;
  }
  // === RequestMessage ===
  RequestMessage::RequestMessage()
    : RequestMessage(KMIP_VERSION_1_4, DEFAULT_MAX_RESPONSE_SIZE) {}

  RequestMessage::RequestMessage(ProtocolVersion version)
    : RequestMessage(std::move(version), DEFAULT_MAX_RESPONSE_SIZE) {}

  RequestMessage::RequestMessage(
      ProtocolVersion version, size_t maxResponseSize
  ) {
    header_.setProtocolVersion(std::move(version));
    setMaxResponseSize(maxResponseSize);
  }

  uint32_t RequestMessage::add_batch_item(RequestBatchItem item) {
    const auto id = nextBatchItemId_++;
    item.setUniqueBatchItemId(id);
    batchItems_.push_back(std::move(item));
    return id;
  }

  void RequestMessage::setBatchItems(
      const std::vector<RequestBatchItem> &items
  ) {
    clearBatchItems();
    for (const auto &item : items) {
      add_batch_item(item);
    }
  }

  void RequestMessage::setMaxResponseSize(size_t size) {
    if (size > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
      throw KmipException(
          "setMaxResponseSize: size_t value " + std::to_string(size) +
          " exceeds int32_t maximum (" +
          std::to_string(std::numeric_limits<int32_t>::max()) + ")"
      );
    }
    header_.setMaximumResponseSize(static_cast<int32_t>(size));
  }

  size_t RequestMessage::getMaxResponseSize() const {
    auto maxResponseSize = header_.getMaximumResponseSize();
    return maxResponseSize ? static_cast<size_t>(*maxResponseSize)
                           : DEFAULT_MAX_RESPONSE_SIZE;
  }

  secure_bytes RequestMessage::serialize() const {
    if (batchItems_.empty()) {
      throw KmipException(
          "Cannot serialize RequestMessage with no batch items"
      );
    }

    RequestMessage request(*this);
    request.header_.setBatchCount(
        static_cast<int32_t>(request.batchItems_.size())
    );
    // BatchOrderOption is only meaningful (and should only be emitted) when
    // the batch contains more than one item.  Sending it for a single-item
    // batch is harmless per the spec but confuses some server implementations.
    if (request.batchItems_.size() > 1 &&
        !request.header_.getBatchOrderOption().has_value()) {
      request.header_.setBatchOrderOption(true);
    }
    request.header_.setTimeStamp(static_cast<int64_t>(time(nullptr)));

    // Maximum Response Size limits the reply, not this request, so it must
    // not size the buffer: the default grows as needed.
    SerializationBuffer buf;
    request.toElement()->serialize(buf);
    return buf.release();
  }

  std::shared_ptr<Element> RequestMessage::toElement() const {
    auto structure = Element::createStructure(tag::KMIP_TAG_REQUEST_MESSAGE);
    structure->asStructure()->add(header_.toElement());
    for (const auto &item : batchItems_) {
      structure->asStructure()->add(item.toElement());
    }
    validate_element_types_for_version(structure, header_.getProtocolVersion());
    return structure;
  }
  RequestMessage RequestMessage::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != tag::KMIP_TAG_REQUEST_MESSAGE ||
        element->type != Type::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid RequestMessage element");
    }
    const auto *s = std::get_if<Structure>(&element->value);
    if (!s) {
      throw KmipException("RequestMessage element does not hold a Structure");
    }
    RequestMessage rm;
    auto hdr = element->getChild(tag::KMIP_TAG_REQUEST_HEADER);
    if (hdr) {
      rm.header_ = RequestHeader::fromElement(hdr);
    } else {
      throw KmipException("Missing Request Header");
    }
    validate_element_types_for_version(
        element, rm.header_.getProtocolVersion()
    );
    for (const auto &child : s->items) {
      if (child->tag == tag::KMIP_TAG_BATCH_ITEM) {
        rm.batchItems_.push_back(RequestBatchItem::fromElement(child));
      }
    }
    if (rm.header_.getBatchCount() !=
        static_cast<int32_t>(rm.batchItems_.size())) {
      throw KmipException(
          "Request Header Batch Count does not match number of Batch Items"
      );
    }
    rm.nextBatchItemId_ = static_cast<uint32_t>(rm.batchItems_.size() + 1);
    return rm;
  }
  // === ResponseHeader ===
  std::shared_ptr<Element> ResponseHeader::toElement() const {
    auto structure = Element::createStructure(tag::KMIP_TAG_RESPONSE_HEADER);
    structure->asStructure()->add(protocolVersion_.toElement());
    structure->asStructure()->add(
        Element::createDateTime(tag::KMIP_TAG_TIME_STAMP, timeStamp_)
    );
    structure->asStructure()->add(
        Element::createInteger(tag::KMIP_TAG_BATCH_COUNT, batchCount_)
    );
    return structure;
  }
  ResponseHeader ResponseHeader::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != tag::KMIP_TAG_RESPONSE_HEADER ||
        element->type != Type::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid ResponseHeader element");
    }
    ResponseHeader rh;
    auto pv = element->getChild(tag::KMIP_TAG_PROTOCOL_VERSION);
    if (pv) {
      rh.protocolVersion_ = ProtocolVersion::fromElement(pv);
    } else {
      throw KmipException("Missing ProtocolVersion");
    }
    auto ts = element->getChild(tag::KMIP_TAG_TIME_STAMP);
    if (ts) {
      rh.timeStamp_ = ts->toLong();
    }
    auto bc = element->getChild(tag::KMIP_TAG_BATCH_COUNT);
    if (bc) {
      rh.batchCount_ = bc->toInt();
    }
    return rh;
  }
  // === ResponseBatchItem ===
  std::shared_ptr<Element> ResponseBatchItem::toElement() const {
    auto structure = Element::createStructure(tag::KMIP_TAG_BATCH_ITEM);
    structure->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_OPERATION, operation_)
    );
    if (uniqueBatchItemId_ != 0) {
      structure->asStructure()->add(
          Element::createByteString(
              tag::KMIP_TAG_UNIQUE_BATCH_ITEM_ID,
              encode_batch_item_id(uniqueBatchItemId_)
          )
      );
    }
    structure->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_RESULT_STATUS, resultStatus_)
    );
    if (resultReason_) {
      structure->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_RESULT_REASON, *resultReason_
          )
      );
    }
    if (resultMessage_) {
      structure->asStructure()->add(
          Element::createTextString(
              tag::KMIP_TAG_RESULT_MESSAGE, *resultMessage_
          )
      );
    }
    if (responsePayload_) {
      structure->asStructure()->add(responsePayload_);
    }
    return structure;
  }
  ResponseBatchItem
      ResponseBatchItem::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != tag::KMIP_TAG_BATCH_ITEM ||
        element->type != Type::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid ResponseBatchItem element");
    }
    ResponseBatchItem rbi;
    auto op = element->getChild(tag::KMIP_TAG_OPERATION);
    if (op) {
      rbi.operation_ = op->toEnum();
    }
    // Operation is optional in responses per KMIP spec §9.1.3: it is only
    // REQUIRED when the request contained more than one Batch Item, or when
    // the result is not Success.  Several real-world servers (e.g. pyKMIP)
    // omit it even in those cases.  Callers that need the effective operation
    // should consult ResponseParser::effectiveOperation() which falls back to
    // the hint derived from the corresponding request batch item.
    auto id = element->getChild(tag::KMIP_TAG_UNIQUE_BATCH_ITEM_ID);
    if (id) {
      auto bytes = id->toBytes();
      std::uint32_t decoded_id = 0;
      if (decode_batch_item_id(bytes, decoded_id)) {
        rbi.uniqueBatchItemId_ = decoded_id;
      }
    }
    auto status = element->getChild(tag::KMIP_TAG_RESULT_STATUS);
    if (status) {
      rbi.resultStatus_ = status->toEnum();
    } else {
      throw KmipException("Missing Result Status");
    }
    auto reason = element->getChild(tag::KMIP_TAG_RESULT_REASON);
    if (reason) {
      rbi.resultReason_ = reason->toEnum();
    }
    if (rbi.resultStatus_ == KMIP_STATUS_OPERATION_FAILED &&
        !rbi.resultReason_.has_value()) {
      throw KmipException(
          "Missing Result Reason for failed response batch item"
      );
    }
    auto msg = element->getChild(tag::KMIP_TAG_RESULT_MESSAGE);
    if (msg) {
      rbi.resultMessage_ = msg->toString();
    }
    auto payload = element->getChild(tag::KMIP_TAG_RESPONSE_PAYLOAD);
    if (payload) {
      rbi.responsePayload_ = payload;
    }
    return rbi;
  }
  // === ResponseMessage ===
  std::shared_ptr<Element> ResponseMessage::toElement() const {
    auto structure = Element::createStructure(tag::KMIP_TAG_RESPONSE_MESSAGE);
    structure->asStructure()->add(header_.toElement());
    for (const auto &item : batchItems_) {
      structure->asStructure()->add(item.toElement());
    }
    validate_element_types_for_version(structure, header_.getProtocolVersion());
    return structure;
  }
  ResponseMessage
      ResponseMessage::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != tag::KMIP_TAG_RESPONSE_MESSAGE ||
        element->type != Type::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid ResponseMessage element");
    }
    const auto *s = std::get_if<Structure>(&element->value);
    if (!s) {
      throw KmipException("ResponseMessage element does not hold a Structure");
    }
    ResponseMessage rm;
    auto hdr = element->getChild(tag::KMIP_TAG_RESPONSE_HEADER);
    if (hdr) {
      rm.header_ = ResponseHeader::fromElement(hdr);
    } else {
      throw KmipException("Missing Response Header");
    }
    validate_element_types_for_version(
        element, rm.header_.getProtocolVersion()
    );
    for (const auto &child : s->items) {
      if (child->tag == tag::KMIP_TAG_BATCH_ITEM) {
        rm.batchItems_.push_back(ResponseBatchItem::fromElement(child));
      }
    }
    // The KMIP spec requires BatchCount to equal the number of BatchItems, but
    // some real-world servers (notably HashiCorp Vault) return a declared count
    // that is higher than the number of items actually present in the body when
    // the first item in a multi-item batch fails (early-stop behaviour).
    // We tolerate under-delivery (fewer items than declared) to stay compatible
    // with those servers.  We only reject the response when it contains MORE
    // items than declared, which would indicate a genuinely malformed message.
    if (static_cast<int32_t>(rm.batchItems_.size()) >
        rm.header_.getBatchCount()) {
      throw KmipException(
          "Response Header Batch Count does not match number of Batch Items"
      );
    }
    return rm;
  }
}  // namespace kmipcore
