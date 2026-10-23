/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// The checks in this file are assert()s; keep them in Release builds, which
// CI runs, rather than compiling them out.
#undef NDEBUG

#include <algorithm>
#include <cassert>
#include <iostream>
#include <kmipcore/kmip_attributes.hpp>
#include <kmipcore/kmip_basics.hpp>
#include <kmipcore/kmip_errors.hpp>
#include <kmipcore/kmip_formatter.hpp>
#include <kmipcore/kmip_protocol.hpp>
#include <kmipcore/kmip_responses.hpp>
#include <kmipcore/secret.hpp>
#include <kmipcore/serialization_buffer.hpp>

using namespace kmipcore;

void test_integer() {
  auto elem = Element::createInteger(tag::KMIP_TAG_ACTIVATION_DATE, 12345);
  SerializationBuffer buf_i;
  elem->serialize(buf_i);
  auto data = buf_i.release();
  assert(data.size() == 16);
  size_t offset = 0;
  auto decoded = Element::deserialize(data, offset);
  assert(offset == 16);
  assert(decoded->tag == tag::KMIP_TAG_ACTIVATION_DATE);
  assert(decoded->type == kmipcore::Type::KMIP_TYPE_INTEGER);
  assert(std::get<Integer>(decoded->value).value == 12345);
  std::cout << "Integer test passed" << std::endl;
}

void test_structure() {
  auto root = Element::createStructure(tag::KMIP_TAG_APPLICATION_DATA);
  auto child1 = Element::createInteger(tag::KMIP_TAG_APPLICATION_NAMESPACE, 10);
  auto child2 = Element::createBoolean(
      tag::KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION, true
  );
  std::get<Structure>(root->value).add(child1);
  std::get<Structure>(root->value).add(child2);
  SerializationBuffer buf_s;
  root->serialize(buf_s);
  auto data = buf_s.release();
  size_t offset = 0;
  auto decoded = Element::deserialize(data, offset);
  assert(decoded->tag == tag::KMIP_TAG_APPLICATION_DATA);
  assert(decoded->type == kmipcore::Type::KMIP_TYPE_STRUCTURE);
  auto &s = std::get<Structure>(decoded->value);
  assert(s.items.size() == 2);
  auto d1 = s.items[0];
  assert(d1->tag == tag::KMIP_TAG_APPLICATION_NAMESPACE);
  assert(std::get<Integer>(d1->value).value == 10);
  auto d2 = s.items[1];
  assert(d2->tag == tag::KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION);
  assert(std::get<Boolean>(d2->value).value == true);
  std::cout << "Structure test passed" << std::endl;
}

void test_date_time_extended_round_trip() {
  constexpr int64_t micros = 1743075078123456LL;

  auto elem = Element::createDateTimeExtended(tag::KMIP_TAG_TIME_STAMP, micros);

  SerializationBuffer buf;
  elem->serialize(buf);
  auto data = buf.release();

  assert(data.size() == 16);
  assert(data[3] == KMIP_TYPE_DATE_TIME_EXTENDED);
  assert(data[4] == 0x00);
  assert(data[5] == 0x00);
  assert(data[6] == 0x00);
  assert(data[7] == 0x08);

  size_t offset = 0;
  auto decoded = Element::deserialize(data, offset);
  assert(offset == 16);
  assert(decoded->tag == tag::KMIP_TAG_TIME_STAMP);
  assert(decoded->type == Type::KMIP_TYPE_DATE_TIME_EXTENDED);
  assert(std::holds_alternative<DateTimeExtended>(decoded->value));
  assert(std::get<DateTimeExtended>(decoded->value).value == micros);
  assert(decoded->toLong() == micros);

  const auto formatted = format_element(decoded);
  assert(formatted.find("DateTimeExtended") != std::string::npos);

  std::cout << "DateTimeExtended round-trip test passed" << std::endl;
}

void test_date_time_extended_invalid_length() {
  const std::vector<uint8_t> invalid = {
      0x42,
      0x00,
      0x92,
      static_cast<uint8_t>(KMIP_TYPE_DATE_TIME_EXTENDED),
      0x00,
      0x00,
      0x00,
      0x04,
      0x00,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x00,
  };

  size_t offset = 0;
  bool threw = false;
  try {
    (void) Element::deserialize(invalid, offset);
  } catch (const KmipException &) {
    threw = true;
  }
  assert(threw);

  std::cout << "DateTimeExtended invalid-length test passed" << std::endl;
}

void test_non_zero_padding_is_rejected() {
  // Text String with declared length 1, but padding bytes must be zero.
  const std::vector<uint8_t> invalid = {
      0x42,
      0x00,
      0x3D,
      static_cast<uint8_t>(KMIP_TYPE_TEXT_STRING),
      0x00,
      0x00,
      0x00,
      0x01,
      static_cast<uint8_t>('A'),
      0xFF,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
  };

  size_t offset = 0;
  bool threw = false;
  try {
    (void) Element::deserialize(invalid, offset);
  } catch (const KmipException &) {
    threw = true;
  }
  assert(threw);

  std::cout << "Non-zero padding validation test passed" << std::endl;
}

// Builds `depth` nested empty Structure elements on the wire, innermost
// first, so the result is a single TTLV tree `depth` levels deep.
std::vector<uint8_t> build_nested_structures(unsigned depth) {
  std::vector<uint8_t> buf;
  for (unsigned i = 0; i < depth; ++i) {
    const auto len = static_cast<uint32_t>(buf.size());
    std::vector<uint8_t> wrapper = {
        0x42,
        0x00,
        0x01,
        static_cast<uint8_t>(KMIP_TYPE_STRUCTURE),
        static_cast<uint8_t>((len >> 24) & 0xFF),
        static_cast<uint8_t>((len >> 16) & 0xFF),
        static_cast<uint8_t>((len >> 8) & 0xFF),
        static_cast<uint8_t>(len & 0xFF),
    };
    wrapper.insert(wrapper.end(), buf.begin(), buf.end());
    buf = std::move(wrapper);
  }
  return buf;
}

void test_deeply_nested_structure_is_rejected() {
  // A malicious server can send arbitrarily deep nesting; the parser must
  // reject it before recursion exhausts the stack.
  const auto data = build_nested_structures(1000);

  size_t offset = 0;
  bool threw = false;
  try {
    (void) Element::deserialize(data, offset);
  } catch (const KmipException &) {
    threw = true;
  }
  assert(threw);

  std::cout << "Deeply nested structure rejection test passed" << std::endl;
}

void test_legitimate_nesting_is_accepted() {
  // Real KMIP messages are only a handful of levels deep; the depth cap must
  // leave comfortable headroom for valid traffic.
  const auto data = build_nested_structures(30);

  size_t offset = 0;
  auto decoded = Element::deserialize(data, offset);
  assert(offset == data.size());
  assert(decoded->type == Type::KMIP_TYPE_STRUCTURE);

  std::cout << "Legitimate nesting acceptance test passed" << std::endl;
}

void test_boolean_non_canonical_rejected() {
  // KMIP 1.4 §9.1.1.4.6: a Boolean must encode exactly 0 or 1. A malicious
  // server sending any other 8-byte payload must be rejected, not collapsed
  // to true.
  auto make_boolean = [](std::uint64_t raw) {
    std::vector<uint8_t> bytes = {
        0x42,
        0x00,
        0x74,
        static_cast<uint8_t>(KMIP_TYPE_BOOLEAN),
        0x00,
        0x00,
        0x00,
        0x08,
    };
    for (int shift = 56; shift >= 0; shift -= 8) {
      bytes.push_back(static_cast<uint8_t>((raw >> shift) & 0xFF));
    }
    return bytes;
  };

  // Canonical values still decode correctly.
  for (std::uint64_t raw : {std::uint64_t{0}, std::uint64_t{1}}) {
    auto bytes = make_boolean(raw);
    size_t offset = 0;
    auto decoded = Element::deserialize(bytes, offset);
    assert(decoded->type == kmipcore::Type::KMIP_TYPE_BOOLEAN);
    assert(std::get<Boolean>(decoded->value).value == (raw == 1));
  }

  // Non-canonical values are rejected.
  for (std::uint64_t raw :
       {std::uint64_t{2}, std::uint64_t{0xFFFFFFFFFFFFFFFFULL}}) {
    auto bytes = make_boolean(raw);
    size_t offset = 0;
    bool threw = false;
    try {
      (void) Element::deserialize(bytes, offset);
    } catch (const KmipException &) {
      threw = true;
    }
    assert(threw);
  }

  std::cout << "Boolean non-canonical rejection test passed" << std::endl;
}

void test_date_time_extended_requires_kmip_2_0_for_requests() {
  RequestBatchItem item;
  item.setOperation(KMIP_OP_GET);

  auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
  payload->asStructure()->add(
      Element::createDateTimeExtended(
          tag::KMIP_TAG_TIME_STAMP, 1743075078123456LL
      )
  );
  item.setRequestPayload(payload);

  RequestMessage request_14;
  request_14.add_batch_item(item);

  bool threw = false;
  try {
    (void) request_14.serialize();
  } catch (const KmipException &) {
    threw = true;
  }
  assert(threw);

  RequestMessage request_20(KMIP_VERSION_2_0);
  assert(request_20.getHeader().getProtocolVersion().getMajor() == 2);
  assert(request_20.getHeader().getProtocolVersion().getMinor() == 0);
  request_20.add_batch_item(item);
  const auto bytes = request_20.serialize();
  assert(!bytes.empty());

  size_t offset = 0;
  auto request_element = Element::deserialize(bytes, offset);
  assert(offset == bytes.size());

  auto request_header = request_element->getChild(tag::KMIP_TAG_REQUEST_HEADER);
  assert(request_header != nullptr);

  auto protocol_version =
      request_header->getChild(tag::KMIP_TAG_PROTOCOL_VERSION);
  assert(protocol_version != nullptr);

  auto parsed_version = ProtocolVersion::fromElement(protocol_version);
  assert(parsed_version.getMajor() == 2);
  assert(parsed_version.getMinor() == 0);

  std::cout << "DateTimeExtended KMIP 2.0 request-version test passed"
            << std::endl;
}

void test_date_time_extended_requires_kmip_2_0_for_responses() {
  auto response = Element::createStructure(tag::KMIP_TAG_RESPONSE_MESSAGE);

  ResponseHeader header;
  header.getProtocolVersion().setMajor(1);
  header.getProtocolVersion().setMinor(4);  // wire minor for KMIP 1.4
  header.setTimeStamp(1234567890);
  header.setBatchCount(1);
  response->asStructure()->add(header.toElement());

  auto batch_item = Element::createStructure(tag::KMIP_TAG_BATCH_ITEM);
  batch_item->asStructure()->add(
      Element::createEnumeration(tag::KMIP_TAG_OPERATION, KMIP_OP_GET)
  );
  batch_item->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_RESULT_STATUS, KMIP_STATUS_SUCCESS
      )
  );

  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(
      Element::createDateTimeExtended(
          tag::KMIP_TAG_TIME_STAMP, 1743075078123456LL
      )
  );
  batch_item->asStructure()->add(payload);
  response->asStructure()->add(batch_item);

  bool threw = false;
  try {
    (void) ResponseMessage::fromElement(response);
  } catch (const KmipException &) {
    threw = true;
  }
  assert(threw);

  header.setProtocolVersion(ProtocolVersion(2, 0));
  auto response_20 = Element::createStructure(tag::KMIP_TAG_RESPONSE_MESSAGE);
  response_20->asStructure()->add(header.toElement());
  response_20->asStructure()->add(batch_item);

  auto parsed = ResponseMessage::fromElement(response_20);
  assert(parsed.getHeader().getProtocolVersion().getMajor() == 2);
  assert(parsed.getHeader().getProtocolVersion().getMinor() == 0);

  std::cout << "DateTimeExtended KMIP 2.0 response-version test passed"
            << std::endl;
}

void test_request_message() {
  RequestMessage req;
  req.getHeader().getProtocolVersion().setMajor(1);
  req.getHeader().getProtocolVersion().setMinor(4);
  req.getHeader().setBatchOrderOption(true);

  RequestBatchItem item;
  item.setOperation(KMIP_OP_GET);  // Some operation code
  // Fake payload
  auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
  payload->asStructure()->add(
      Element::createInteger(tag::KMIP_TAG_ACTIVATION_DATE, 999)
  );
  item.setRequestPayload(payload);
  auto first_id = req.add_batch_item(item);

  RequestBatchItem item2;
  item2.setOperation(KMIP_OP_GET_ATTRIBUTE_LIST);
  auto payload2 = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
  payload2->asStructure()->add(
      Element::createInteger(tag::KMIP_TAG_ACTIVATION_DATE, 111)
  );
  item2.setRequestPayload(payload2);
  auto second_id = req.add_batch_item(item2);

  assert(first_id == 1);
  assert(second_id == 2);
  assert(first_id != second_id);

  auto bytes = req.serialize();
  std::cout << "Serialized RequestMessage size: " << bytes.size() << std::endl;
  size_t offset = 0;
  auto deserialized = Element::deserialize(bytes, offset);

  auto encoded_batch_items =
      deserialized->getChildren(tag::KMIP_TAG_BATCH_ITEM);
  assert(encoded_batch_items.size() == 2);
  auto first_encoded_id =
      encoded_batch_items[0]->getChild(tag::KMIP_TAG_UNIQUE_BATCH_ITEM_ID);
  auto second_encoded_id =
      encoded_batch_items[1]->getChild(tag::KMIP_TAG_UNIQUE_BATCH_ITEM_ID);
  assert(first_encoded_id != nullptr);
  assert(second_encoded_id != nullptr);
  const auto first_id_bytes = first_encoded_id->toBytes();
  const auto second_id_bytes = second_encoded_id->toBytes();
  assert(first_id_bytes.size() == 4);
  assert(second_id_bytes.size() == 4);
  assert(
      first_id_bytes[0] == 0x00 && first_id_bytes[1] == 0x00 &&
      first_id_bytes[2] == 0x00 && first_id_bytes[3] == 0x01
  );
  assert(
      second_id_bytes[0] == 0x00 && second_id_bytes[1] == 0x00 &&
      second_id_bytes[2] == 0x00 && second_id_bytes[3] == 0x02
  );

  auto req2 = RequestMessage::fromElement(deserialized);
  assert(req2.getHeader().getProtocolVersion().getMajor() == 1);
  assert(req2.getHeader().getBatchOrderOption().has_value());
  assert(req2.getHeader().getBatchOrderOption().value() == true);
  assert(req2.getBatchItems().size() == 2);
  assert(req2.getBatchItems()[0].getUniqueBatchItemId() == 1u);
  assert(req2.getBatchItems()[1].getUniqueBatchItemId() == 2u);
  assert(req2.getBatchItems()[0].getOperation() == KMIP_OP_GET);
  assert(req2.getBatchItems()[1].getOperation() == KMIP_OP_GET_ATTRIBUTE_LIST);
  std::cout << "RequestMessage test passed" << std::endl;
}
void test_response_message() {
  ResponseMessage resp;
  resp.getHeader().getProtocolVersion().setMajor(1);
  resp.getHeader().getProtocolVersion().setMinor(4);
  resp.getHeader().setTimeStamp(1678886400);  // 2023-03-15 or so
  resp.getHeader().setBatchCount(2);

  ResponseBatchItem get_item;
  get_item.setUniqueBatchItemId(0x01020304u);
  get_item.setOperation(KMIP_OP_GET);
  get_item.setResultStatus(KMIP_STATUS_SUCCESS);  // Success
  get_item.setResultMessage("OK");

  auto get_payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  get_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "id-get-1")
  );
  get_payload->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SYMMETRIC_KEY
      )
  );
  auto symmetric_key = Element::createStructure(tag::KMIP_TAG_SYMMETRIC_KEY);
  auto key_block = Element::createStructure(tag::KMIP_TAG_KEY_BLOCK);
  key_block->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_KEY_FORMAT_TYPE, KMIP_KEYFORMAT_RAW
      )
  );
  auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
  key_value->asStructure()->add(
      Element::createByteString(
          tag::KMIP_TAG_KEY_MATERIAL, {0x10, 0x11, 0x12, 0x13}
      )
  );
  key_block->asStructure()->add(key_value);
  symmetric_key->asStructure()->add(key_block);
  get_payload->asStructure()->add(symmetric_key);
  get_item.setResponsePayload(get_payload);
  resp.add_batch_item(get_item);

  ResponseBatchItem locate_item;
  locate_item.setOperation(KMIP_OP_LOCATE);
  locate_item.setResultStatus(KMIP_STATUS_SUCCESS);
  auto locate_payload =
      Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  locate_payload->asStructure()->add(
      Element::createInteger(tag::KMIP_TAG_LOCATED_ITEMS, 2)
  );
  locate_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "id-locate-1")
  );
  locate_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "id-locate-2")
  );
  locate_item.setResponsePayload(locate_payload);
  resp.add_batch_item(locate_item);

  auto elem = resp.toElement();
  SerializationBuffer buf_r;
  elem->serialize(buf_r);
  auto bytes = buf_r.release();
  size_t offset = 0;
  auto deserialized = Element::deserialize(bytes, offset);
  auto resp2 = ResponseMessage::fromElement(deserialized);
  assert(resp2.getHeader().getTimeStamp() == 1678886400);
  assert(resp2.getBatchItems().size() == 2);
  assert(resp2.getBatchItems()[0].getResultStatus() == KMIP_STATUS_SUCCESS);
  assert(*resp2.getBatchItems()[0].getResultMessage() == "OK");
  assert(resp2.getBatchItems()[1].getOperation() == KMIP_OP_LOCATE);
  std::cout << "ResponseMessage test passed" << std::endl;
}
void test_typed_response_batch_items() {
  auto create_payload =
      Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  create_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "create-id")
  );

  ResponseBatchItem create_item;
  create_item.setOperation(KMIP_OP_CREATE);
  create_item.setResultStatus(KMIP_STATUS_SUCCESS);
  create_item.setResponsePayload(create_payload);

  auto create_response = CreateResponseBatchItem::fromBatchItem(create_item);
  assert(create_response.getUniqueIdentifier() == "create-id");

  auto get_payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  get_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "get-id")
  );
  get_payload->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SECRET_DATA
      )
  );
  auto secret_data = Element::createStructure(tag::KMIP_TAG_SECRET_DATA);
  auto key_block = Element::createStructure(tag::KMIP_TAG_KEY_BLOCK);
  auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
  key_value->asStructure()->add(
      Element::createByteString(tag::KMIP_TAG_KEY_MATERIAL, {0x61, 0x62})
  );
  key_block->asStructure()->add(key_value);
  secret_data->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_SECRET_DATA_TYPE,
          static_cast<int32_t>(secret_data_type::KMIP_SECDATA_PASSWORD)
      )
  );
  secret_data->asStructure()->add(key_block);
  get_payload->asStructure()->add(secret_data);

  ResponseBatchItem get_item;
  get_item.setOperation(KMIP_OP_GET);
  get_item.setResultStatus(KMIP_STATUS_SUCCESS);
  get_item.setResponsePayload(get_payload);

  auto get_response = GetResponseBatchItem::fromBatchItem(get_item);
  assert(get_response.getUniqueIdentifier() == "get-id");
  assert(get_response.getObjectType() == KMIP_OBJTYPE_SECRET_DATA);
  assert(get_response.getObjectElement() != nullptr);

  auto attributes_payload =
      Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  attribute->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "State")
  );
  attribute->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_ATTRIBUTE_VALUE, KMIP_STATE_ACTIVE
      )
  );
  attributes_payload->asStructure()->add(attribute);

  ResponseBatchItem attributes_item;
  attributes_item.setOperation(KMIP_OP_GET_ATTRIBUTES);
  attributes_item.setResultStatus(KMIP_STATUS_SUCCESS);
  attributes_item.setResponsePayload(attributes_payload);

  auto attributes_response =
      GetAttributesResponseBatchItem::fromBatchItem(attributes_item);
  assert(attributes_response.getAttributes().size() == 1);

  auto attribute_list_payload =
      Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  attribute_list_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "Name")
  );
  attribute_list_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "State")
  );

  ResponseBatchItem attribute_list_item;
  attribute_list_item.setOperation(KMIP_OP_GET_ATTRIBUTE_LIST);
  attribute_list_item.setResultStatus(KMIP_STATUS_SUCCESS);
  attribute_list_item.setResponsePayload(attribute_list_payload);

  auto attribute_list_response =
      GetAttributeListResponseBatchItem::fromBatchItem(attribute_list_item);
  assert(attribute_list_response.getAttributeNames().size() == 2);
  assert(attribute_list_response.getAttributeNames()[0] == "Name");

  auto locate_payload =
      Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  locate_payload->asStructure()->add(
      Element::createInteger(tag::KMIP_TAG_LOCATED_ITEMS, 2)
  );
  locate_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "loc-1")
  );
  locate_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "loc-2")
  );

  ResponseBatchItem locate_item;
  locate_item.setOperation(KMIP_OP_LOCATE);
  locate_item.setResultStatus(KMIP_STATUS_SUCCESS);
  locate_item.setResponsePayload(locate_payload);

  auto locate_response = LocateResponseBatchItem::fromBatchItem(locate_item);
  assert(locate_response.getLocatePayload().getLocatedItems().value() == 2);
  assert(locate_response.getUniqueIdentifiers().size() == 2);

  auto discover_payload =
      Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  discover_payload->asStructure()->add(ProtocolVersion(2, 0).toElement());
  discover_payload->asStructure()->add(ProtocolVersion(1, 4).toElement());

  ResponseBatchItem discover_item;
  discover_item.setOperation(KMIP_OP_DISCOVER_VERSIONS);
  discover_item.setResultStatus(KMIP_STATUS_SUCCESS);
  discover_item.setResponsePayload(discover_payload);

  auto discover_response =
      DiscoverVersionsResponseBatchItem::fromBatchItem(discover_item);
  assert(discover_response.getProtocolVersions().size() == 2);
  assert(discover_response.getProtocolVersions()[0].getMajor() == 2);
  assert(discover_response.getProtocolVersions()[0].getMinor() == 0);
  assert(discover_response.getProtocolVersions()[1].getMajor() == 1);
  assert(discover_response.getProtocolVersions()[1].getMinor() == 4);

  ResponseBatchItem discover_empty_item;
  discover_empty_item.setOperation(KMIP_OP_DISCOVER_VERSIONS);
  discover_empty_item.setResultStatus(KMIP_STATUS_SUCCESS);

  auto discover_empty_response =
      DiscoverVersionsResponseBatchItem::fromBatchItem(discover_empty_item);
  assert(discover_empty_response.getProtocolVersions().empty());

  auto query_payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  query_payload->asStructure()->add(
      Element::createEnumeration(tag::KMIP_TAG_OPERATION, KMIP_OP_GET)
  );
  query_payload->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SECRET_DATA
      )
  );
  query_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_VENDOR_IDENTIFICATION, "VendorX")
  );
  auto query_server_info =
      Element::createStructure(tag::KMIP_TAG_SERVER_INFORMATION);
  query_server_info->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_SERVER_NAME, "node-a")
  );
  query_payload->asStructure()->add(query_server_info);

  ResponseBatchItem query_item;
  query_item.setOperation(KMIP_OP_QUERY);
  query_item.setResultStatus(KMIP_STATUS_SUCCESS);
  query_item.setResponsePayload(query_payload);

  auto query_response = QueryResponseBatchItem::fromBatchItem(query_item);
  assert(query_response.getOperations().size() == 1);
  assert(query_response.getOperations()[0] == KMIP_OP_GET);
  assert(query_response.getObjectTypes().size() == 1);
  assert(query_response.getObjectTypes()[0] == KMIP_OBJTYPE_SECRET_DATA);
  assert(query_response.getVendorIdentification() == "VendorX");
  assert(query_response.getServerName() == "node-a");

  ResponseBatchItem query_empty_item;
  query_empty_item.setOperation(KMIP_OP_QUERY);
  query_empty_item.setResultStatus(KMIP_STATUS_SUCCESS);
  auto query_empty_response =
      QueryResponseBatchItem::fromBatchItem(query_empty_item);
  assert(query_empty_response.getOperations().empty());
  assert(query_empty_response.getObjectTypes().empty());

  ResponseBatchItem destroy_item;
  destroy_item.setOperation(KMIP_OP_DESTROY);
  destroy_item.setResultStatus(KMIP_STATUS_SUCCESS);
  auto destroy_payload =
      Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  destroy_payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "destroy-id")
  );
  destroy_item.setResponsePayload(destroy_payload);

  auto destroy_response = DestroyResponseBatchItem::fromBatchItem(destroy_item);
  assert(destroy_response.getUniqueIdentifier() == "destroy-id");

  std::cout << "Typed response batch item tests passed" << std::endl;
}

void test_locate_payload() {
  LocateRequestPayload locReq;
  locReq.setMaximumItems(10);
  locReq.setOffsetItems(5);
  locReq.addAttribute(Attribute("Name", "Key1"));

  auto elem = locReq.toElement();
  SerializationBuffer buf_l;
  elem->serialize(buf_l);
  auto bytes = buf_l.release();

  size_t offset = 0;
  auto deserialized = Element::deserialize(bytes, offset);
  auto locReq2 = LocateRequestPayload::fromElement(deserialized);

  assert(locReq2.getMaximumItems() == 10);
  assert(locReq2.getOffsetItems() == 5);
  assert(locReq2.getAttributes().size() == 1);
  assert(locReq2.getAttributes()[0].getName() == "Name");

  std::cout << "Locate Payload test passed" << std::endl;
}

void test_response_required_fields() {
  {
    // Missing ResponseHeader must be rejected.
    auto response_message =
        Element::createStructure(tag::KMIP_TAG_RESPONSE_MESSAGE);
    auto batch_item = Element::createStructure(tag::KMIP_TAG_BATCH_ITEM);
    batch_item->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_OPERATION, KMIP_OP_GET)
    );
    batch_item->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_RESULT_STATUS, KMIP_STATUS_SUCCESS
        )
    );
    response_message->asStructure()->add(batch_item);

    bool threw = false;
    try {
      (void) ResponseMessage::fromElement(response_message);
    } catch (const KmipException &) {
      threw = true;
    }
    assert(threw);
  }

  {
    // Header Batch Count > actual items: tolerated for Vault compatibility
    // (Vault declares BatchCount=N but returns fewer items on early stop).
    auto response_message =
        Element::createStructure(tag::KMIP_TAG_RESPONSE_MESSAGE);

    ResponseHeader header;
    header.getProtocolVersion().setMajor(1);
    header.getProtocolVersion().setMinor(4);
    header.setTimeStamp(1234567890);
    header.setBatchCount(2);
    response_message->asStructure()->add(header.toElement());

    auto batch_item = Element::createStructure(tag::KMIP_TAG_BATCH_ITEM);
    batch_item->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_OPERATION, KMIP_OP_GET)
    );
    batch_item->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_RESULT_STATUS, KMIP_STATUS_SUCCESS
        )
    );
    response_message->asStructure()->add(batch_item);

    // Must NOT throw: under-delivery (fewer items than declared) is accepted.
    bool threw = false;
    try {
      (void) ResponseMessage::fromElement(response_message);
    } catch (const KmipException &) {
      threw = true;
    }
    assert(!threw);
  }

  {
    // Header Batch Count < actual items: still rejected (truly malformed).
    auto response_message =
        Element::createStructure(tag::KMIP_TAG_RESPONSE_MESSAGE);

    ResponseHeader header;
    header.getProtocolVersion().setMajor(1);
    header.getProtocolVersion().setMinor(4);
    header.setTimeStamp(1234567890);
    header.setBatchCount(1);
    response_message->asStructure()->add(header.toElement());

    auto make_success_item = [](int32_t op) {
      auto item = Element::createStructure(tag::KMIP_TAG_BATCH_ITEM);
      item->asStructure()->add(
          Element::createEnumeration(tag::KMIP_TAG_OPERATION, op)
      );
      item->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_RESULT_STATUS, KMIP_STATUS_SUCCESS
          )
      );
      return item;
    };
    response_message->asStructure()->add(make_success_item(KMIP_OP_GET));
    response_message->asStructure()->add(
        make_success_item(KMIP_OP_GET_ATTRIBUTES)
    );

    bool threw = false;
    try {
      (void) ResponseMessage::fromElement(response_message);
    } catch (const KmipException &) {
      threw = true;
    }
    assert(threw);
  }

  {
    // Missing Result Status must be rejected.
    auto response_message =
        Element::createStructure(tag::KMIP_TAG_RESPONSE_MESSAGE);

    ResponseHeader header;
    header.getProtocolVersion().setMajor(1);
    header.getProtocolVersion().setMinor(4);
    header.setTimeStamp(1234567890);
    header.setBatchCount(1);
    response_message->asStructure()->add(header.toElement());

    auto batch_item = Element::createStructure(tag::KMIP_TAG_BATCH_ITEM);
    batch_item->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_OPERATION, KMIP_OP_GET)
    );
    response_message->asStructure()->add(batch_item);

    bool threw = false;
    try {
      (void) ResponseMessage::fromElement(response_message);
    } catch (const KmipException &) {
      threw = true;
    }
    assert(threw);
  }

  {
    // Result Reason is required when Result Status is Operation Failed.
    auto response_message =
        Element::createStructure(tag::KMIP_TAG_RESPONSE_MESSAGE);

    ResponseHeader header;
    header.getProtocolVersion().setMajor(1);
    header.getProtocolVersion().setMinor(4);
    header.setTimeStamp(1234567890);
    header.setBatchCount(1);
    response_message->asStructure()->add(header.toElement());

    auto batch_item = Element::createStructure(tag::KMIP_TAG_BATCH_ITEM);
    batch_item->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_OPERATION, KMIP_OP_GET)
    );
    batch_item->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_RESULT_STATUS, KMIP_STATUS_OPERATION_FAILED
        )
    );
    response_message->asStructure()->add(batch_item);

    bool threw = false;
    try {
      (void) ResponseMessage::fromElement(response_message);
    } catch (const KmipException &) {
      threw = true;
    }
    assert(threw);
  }

  {
    // Missing Operation inside ResponseBatchItem is now accepted: the field is
    // optional for responses per the KMIP spec and several real-world servers
    // (e.g. pyKMIP) omit it.  The operation defaults to 0; callers should use
    // the ResponseParser operation-hint mechanism to recover the expected
    // value.
    auto response_message =
        Element::createStructure(tag::KMIP_TAG_RESPONSE_MESSAGE);

    ResponseHeader header;
    header.getProtocolVersion().setMajor(1);
    header.getProtocolVersion().setMinor(4);
    header.setTimeStamp(1234567890);
    header.setBatchCount(1);
    response_message->asStructure()->add(header.toElement());

    auto batch_item = Element::createStructure(tag::KMIP_TAG_BATCH_ITEM);
    batch_item->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_RESULT_STATUS, KMIP_STATUS_SUCCESS
        )
    );
    response_message->asStructure()->add(batch_item);

    // Parse must succeed without throwing.
    auto parsed = ResponseMessage::fromElement(response_message);
    assert(parsed.getBatchItems().size() == 1);
    // Operation field is absent → defaults to 0.
    assert(parsed.getBatchItems()[0].getOperation() == 0);
  }

  std::cout << "Response required-fields validation test passed" << std::endl;
}

void test_message_root_must_hold_structure_value() {
  // An Element whose declared type is STRUCTURE but whose variant holds a
  // different alternative must be rejected with a clear error instead of
  // dereferencing the null result of std::get_if<Structure>.
  {
    auto element = std::make_shared<Element>(
        tag::KMIP_TAG_REQUEST_MESSAGE, Type::KMIP_TYPE_STRUCTURE, Integer{0}
    );
    bool threw = false;
    try {
      (void) RequestMessage::fromElement(element);
    } catch (const KmipException &e) {
      threw = std::string(e.what()).find("Structure") != std::string::npos;
    }
    assert(threw);
  }

  {
    auto element = std::make_shared<Element>(
        tag::KMIP_TAG_RESPONSE_MESSAGE, Type::KMIP_TYPE_STRUCTURE, Integer{0}
    );
    bool threw = false;
    try {
      (void) ResponseMessage::fromElement(element);
    } catch (const KmipException &e) {
      threw = std::string(e.what()).find("Structure") != std::string::npos;
    }
    assert(threw);
  }

  std::cout << "Message root structure-value test passed" << std::endl;
}

void test_request_header_authentication() {
  RequestHeader header;
  header.getProtocolVersion().setMajor(1);
  header.getProtocolVersion().setMinor(4);
  header.setBatchCount(1);
  header.setUserName(std::string("alice"));
  header.setPassword(std::string("s3cr3t"));

  auto element = header.toElement();
  auto auth = element->getChild(tag::KMIP_TAG_AUTHENTICATION);
  assert(auth != nullptr);

  auto credential = auth->getChild(tag::KMIP_TAG_CREDENTIAL);
  assert(credential != nullptr);

  auto credential_type = credential->getChild(tag::KMIP_TAG_CREDENTIAL_TYPE);
  assert(credential_type != nullptr);
  assert(credential_type->toEnum() == KMIP_CRED_USERNAME_AND_PASSWORD);

  auto credential_value = credential->getChild(tag::KMIP_TAG_CREDENTIAL_VALUE);
  assert(credential_value != nullptr);

  auto username = credential_value->getChild(tag::KMIP_TAG_USERNAME);
  assert(username != nullptr);
  assert(username->toString() == "alice");

  auto password = credential_value->getChild(tag::KMIP_TAG_PASSWORD);
  assert(password != nullptr);
  assert(password->toString() == "s3cr3t");

  auto parsed = RequestHeader::fromElement(element);
  assert(parsed.getUserName().has_value());
  assert(parsed.getPassword().has_value());
  assert(parsed.getUserName().value() == "alice");
  assert(parsed.getPassword().value() == "s3cr3t");

  std::cout << "RequestHeader authentication test passed" << std::endl;
}

void test_max_response_size_range_check() {
  // Test that setMaxResponseSize rejects values > INT32_MAX
  RequestMessage req;

  // Valid: fits in int32_t
  req.setMaxResponseSize(1000);
  assert(req.getMaxResponseSize() == 1000);

  // Valid: exact INT32_MAX
  req.setMaxResponseSize(2147483647);  // INT32_MAX
  assert(req.getMaxResponseSize() == 2147483647);

  // Invalid: exceeds INT32_MAX
  try {
    req.setMaxResponseSize(2147483648UL);  // INT32_MAX + 1
    assert(false && "Should have thrown on overflow");
  } catch (const KmipException &e) {
    assert(
        std::string(e.what()).find("exceeds int32_t maximum") !=
        std::string::npos
    );
  }

  // Invalid: very large size_t value
  try {
    req.setMaxResponseSize(18446744073709551615UL);  // SIZE_MAX on 64-bit
    assert(false && "Should have thrown on overflow");
  } catch (const KmipException &e) {
    assert(
        std::string(e.what()).find("exceeds int32_t maximum") !=
        std::string::npos
    );
  }

  std::cout << "MaxResponseSize range check test passed" << std::endl;
}

void test_default_max_response_size() {
  RequestMessage req;
  assert(req.getMaxResponseSize() == KMIP_MAX_MESSAGE_SIZE);
  std::cout << "Default MaxResponseSize test passed" << std::endl;
}

void test_attributes_set_c_string() {
  Attributes attrs;
  // A string literal must not bind to the bool overload.
  attrs.set("x-literal", "value");
  assert(attrs.get("x-literal") == "value");
  const char *null_value = nullptr;
  attrs.set("x-null", null_value);
  assert(attrs.has_attribute("x-null"));
  assert(attrs.get("x-null").empty());
  std::cout << "Attributes set(const char *) test passed" << std::endl;
}

void test_secret_from_text() {
  // Every byte of the text is kept, including an embedded NUL and bytes
  // above 0x7F.
  const std::string text("pa\0ss\xC3\xA9", 7);
  auto secret = Secret::from_text(
      text, secret_data_type::KMIP_SECDATA_SEED, state::KMIP_STATE_ACTIVE
  );
  assert(secret.value().size() == text.size());
  assert(
      std::equal(
          secret.value().begin(),
          secret.value().end(),
          text.begin(),
          text.end(),
          [](unsigned char a, char b) {
            return a == static_cast<unsigned char>(b);
          }
      )
  );
  assert(secret.as_text() == text);
  assert(secret.get_secret_type() == secret_data_type::KMIP_SECDATA_SEED);
  assert(secret.get_state() == state::KMIP_STATE_ACTIVE);

  auto empty = Secret::from_text("");
  assert(empty.value().empty());
  assert(empty.get_secret_type() == secret_data_type::KMIP_SECDATA_PASSWORD);
  assert(empty.get_state() == state::KMIP_STATE_PRE_ACTIVE);

  std::cout << "Secret from_text test passed" << std::endl;
}

int main() {
  test_integer();
  test_structure();
  test_date_time_extended_round_trip();
  test_date_time_extended_invalid_length();
  test_non_zero_padding_is_rejected();
  test_deeply_nested_structure_is_rejected();
  test_legitimate_nesting_is_accepted();
  test_boolean_non_canonical_rejected();
  test_date_time_extended_requires_kmip_2_0_for_requests();
  test_date_time_extended_requires_kmip_2_0_for_responses();
  test_request_message();
  test_response_message();
  test_typed_response_batch_items();
  test_locate_payload();
  test_response_required_fields();
  test_message_root_must_hold_structure_value();
  test_request_header_authentication();
  test_max_response_size_range_check();
  test_default_max_response_size();
  test_attributes_set_c_string();
  test_secret_from_text();
  return 0;
}
