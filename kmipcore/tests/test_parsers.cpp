/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// The checks in this file are assert()s; keep them in Release builds, which
// CI runs, rather than compiling them out.
#undef NDEBUG

#include "kmipcore/attributes_parser.hpp"
#include "kmipcore/key_parser.hpp"
#include "kmipcore/kmip_attribute_names.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/kmip_formatter.hpp"
#include "kmipcore/kmip_logger.hpp"
#include "kmipcore/kmip_requests.hpp"
#include "kmipcore/response_parser.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <optional>
#include <utility>
#include <vector>

using namespace kmipcore;

namespace {

  class CollectingLogger : public Logger {
  public:
    [[nodiscard]] bool shouldLog(LogLevel level) const override {
      return level == LogLevel::Debug;
    }

    void log(const LogRecord &record) override { records.push_back(record); }

    std::vector<LogRecord> records;
  };

}  // namespace

secure_bytes create_mock_response_bytes_with_result(
    int32_t operation,
    std::shared_ptr<Element> payload,
    int32_t result_status,
    std::optional<int32_t> result_reason,
    const std::optional<std::string> &result_message
);

// Helper to create a basic success response message with one item
secure_bytes create_mock_response_bytes(
    int32_t operation, std::shared_ptr<Element> payload
) {
  return create_mock_response_bytes_with_result(
      operation,
      std::move(payload),
      KMIP_STATUS_SUCCESS,
      std::nullopt,
      std::nullopt
  );
}

secure_bytes create_mock_response_bytes_with_result(
    int32_t operation,
    std::shared_ptr<Element> payload,
    int32_t result_status,
    std::optional<int32_t> result_reason,
    const std::optional<std::string> &result_message
) {
  ResponseMessage resp;
  resp.getHeader().getProtocolVersion().setMajor(1);
  resp.getHeader().getProtocolVersion().setMinor(4);  // wire minor for KMIP 1.4
  resp.getHeader().setTimeStamp(1234567890);
  resp.getHeader().setBatchCount(1);

  ResponseBatchItem item;
  item.setUniqueBatchItemId(1);
  item.setOperation(operation);
  item.setResultStatus(result_status);
  item.setResultReason(result_reason);
  item.setResultMessage(result_message);
  if (payload) {
    item.setResponsePayload(std::move(payload));
  }

  resp.add_batch_item(item);
  SerializationBuffer buf;
  resp.toElement()->serialize(buf);
  return buf.release();
}

void test_response_parser_failure_preserves_reason_code() {
  auto bytes = create_mock_response_bytes_with_result(
      KMIP_OP_GET,
      nullptr,
      KMIP_STATUS_OPERATION_FAILED,
      KMIP_REASON_ITEM_NOT_FOUND,
      std::string("Object missing")
  );
  ResponseParser parser(bytes);

  bool threw = false;
  try {
    [[maybe_unused]] auto resp = parser.getResponse<GetResponseBatchItem>(0);
  } catch (const KmipException &e) {
    threw = true;
    assert(e.code().value() == KMIP_REASON_ITEM_NOT_FOUND);
  }

  assert(threw);
  std::cout << "ResponseParser failure reason-code preservation test passed"
            << std::endl;
}

// Helper: build a response where the Operation tag is intentionally omitted
// (simulates the pyKMIP behaviour of omitting Operation in failure responses).
secure_bytes create_mock_response_bytes_no_operation(
    int32_t result_status,
    std::optional<int32_t> result_reason,
    const std::optional<std::string> &result_message,
    uint32_t unique_batch_item_id = 1
) {
  ResponseMessage resp;
  resp.getHeader().getProtocolVersion().setMajor(2);
  resp.getHeader().getProtocolVersion().setMinor(0);
  resp.getHeader().setTimeStamp(1234567890);
  resp.getHeader().setBatchCount(1);

  ResponseBatchItem item;
  item.setUniqueBatchItemId(unique_batch_item_id);
  // Intentionally do NOT call item.setOperation() – mirrors pyKMIP behaviour.
  item.setResultStatus(result_status);
  item.setResultReason(result_reason);
  item.setResultMessage(result_message);

  resp.add_batch_item(item);
  SerializationBuffer buf;
  resp.toElement()->serialize(buf);
  return buf.release();
}

void test_response_parser_operation_hint_when_operation_absent() {
  // Build a failure response with no Operation tag (as pyKMIP sends).
  auto bytes = create_mock_response_bytes_no_operation(
      KMIP_STATUS_OPERATION_FAILED,
      KMIP_REASON_ITEM_NOT_FOUND,
      std::string("Not found")
  );

  // ── Case 1: parser without hints → should not crash during parse, but
  //    the operation in the thrown error is 0 ("Unknown Operation").
  {
    ResponseParser parser(bytes);
    bool threw = false;
    try {
      [[maybe_unused]] auto resp = parser.getResponse<GetResponseBatchItem>(0);
    } catch (const KmipException &e) {
      threw = true;
      assert(e.code().value() == KMIP_REASON_ITEM_NOT_FOUND);
      // Operation string should be the "unknown" fallback.
      const std::string msg = e.what();
      assert(msg.find("Operation: Unknown Operation") != std::string::npos);
    }
    assert(threw);
  }

  // ── Case 2: parser WITH hints → error message should show the correct op.
  {
    // Craft a minimal request that matches the batch item id (1).
    RequestMessage request;
    request.add_batch_item(GetRequest("fake-id-abc"));

    ResponseParser parser(bytes, request);
    bool threw = false;
    try {
      [[maybe_unused]] auto resp = parser.getResponse<GetResponseBatchItem>(0);
    } catch (const KmipException &e) {
      threw = true;
      assert(e.code().value() == KMIP_REASON_ITEM_NOT_FOUND);
      const std::string msg = e.what();
      // With the hint the error should now say "Operation: Get".
      assert(msg.find("Operation: Get") != std::string::npos);
      assert(msg.find("Result reason:") != std::string::npos);
    }
    assert(threw);
  }

  std::cout << "ResponseParser operation-hint fallback test passed"
            << std::endl;
}

void test_response_parser_create() {
  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SYMMETRIC_KEY
      )
  );
  payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "uuid-1234")
  );

  auto bytes = create_mock_response_bytes(KMIP_OP_CREATE, payload);
  ResponseParser parser(bytes);

  assert(parser.getBatchItemCount() == 1);
  assert(parser.isSuccess(0));

  auto result = parser.getOperationResult(0);
  assert(result.operation == KMIP_OP_CREATE);
  assert(result.resultStatus == KMIP_STATUS_SUCCESS);

  auto create_resp = parser.getResponse<CreateResponseBatchItem>(0);
  assert(create_resp.getUniqueIdentifier() == "uuid-1234");

  std::cout << "ResponseParser Create test passed" << std::endl;
}

void test_response_parser_locate() {
  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(
      Element::createInteger(tag::KMIP_TAG_LOCATED_ITEMS, 2)
  );
  payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "uuid-1")
  );
  payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "uuid-2")
  );

  auto bytes = create_mock_response_bytes(KMIP_OP_LOCATE, payload);
  ResponseParser parser(bytes);

  auto locate_resp = parser.getResponse<LocateResponseBatchItem>(0);
  assert(locate_resp.getLocatePayload().getUniqueIdentifiers().size() == 2);
  assert(locate_resp.getUniqueIdentifiers()[0] == "uuid-1");
  assert(locate_resp.getUniqueIdentifiers()[1] == "uuid-2");

  std::cout << "ResponseParser Locate test passed" << std::endl;
}

void test_response_parser_discover_versions() {
  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(ProtocolVersion(2, 1).toElement());
  payload->asStructure()->add(ProtocolVersion(2, 0).toElement());
  payload->asStructure()->add(ProtocolVersion(1, 4).toElement());

  auto bytes = create_mock_response_bytes(KMIP_OP_DISCOVER_VERSIONS, payload);
  ResponseParser parser(bytes);

  auto discover_resp = parser.getResponse<DiscoverVersionsResponseBatchItem>(0);
  const auto &versions = discover_resp.getProtocolVersions();
  assert(versions.size() == 3);
  assert(versions[0].getMajor() == 2 && versions[0].getMinor() == 1);
  assert(versions[1].getMajor() == 2 && versions[1].getMinor() == 0);
  assert(versions[2].getMajor() == 1 && versions[2].getMinor() == 4);

  std::cout << "ResponseParser Discover Versions test passed" << std::endl;
}

void test_response_parser_discover_versions_empty_payload() {
  auto bytes = create_mock_response_bytes(KMIP_OP_DISCOVER_VERSIONS, nullptr);
  ResponseParser parser(bytes);

  auto discover_resp = parser.getResponse<DiscoverVersionsResponseBatchItem>(0);
  assert(discover_resp.getProtocolVersions().empty());

  std::cout << "ResponseParser Discover Versions empty-payload test passed"
            << std::endl;
}

void test_response_parser_query() {
  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(
      Element::createEnumeration(tag::KMIP_TAG_OPERATION, KMIP_OP_GET)
  );
  payload->asStructure()->add(
      Element::createEnumeration(tag::KMIP_TAG_OPERATION, KMIP_OP_CREATE)
  );
  payload->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SYMMETRIC_KEY
      )
  );
  payload->asStructure()->add(
      Element::createTextString(
          tag::KMIP_TAG_VENDOR_IDENTIFICATION, "ExampleVendor"
      )
  );

  auto server_info = Element::createStructure(tag::KMIP_TAG_SERVER_INFORMATION);
  server_info->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_SERVER_NAME, "example-kmip")
  );
  server_info->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_SERVER_VERSION, "2.0.1")
  );
  payload->asStructure()->add(server_info);

  auto bytes = create_mock_response_bytes(KMIP_OP_QUERY, payload);
  ResponseParser parser(bytes);

  auto query_resp = parser.getResponse<QueryResponseBatchItem>(0);
  assert(query_resp.getOperations().size() == 2);
  assert(query_resp.getOperations()[0] == KMIP_OP_GET);
  assert(query_resp.getObjectTypes().size() == 1);
  assert(query_resp.getObjectTypes()[0] == KMIP_OBJTYPE_SYMMETRIC_KEY);
  assert(query_resp.getVendorIdentification() == "ExampleVendor");
  assert(query_resp.getServerName() == "example-kmip");
  assert(query_resp.getServerVersion() == "2.0.1");

  std::cout << "ResponseParser Query test passed" << std::endl;
}

void test_response_parser_query_empty_payload() {
  auto bytes = create_mock_response_bytes(KMIP_OP_QUERY, nullptr);
  ResponseParser parser(bytes);

  auto query_resp = parser.getResponse<QueryResponseBatchItem>(0);
  assert(query_resp.getOperations().empty());
  assert(query_resp.getObjectTypes().empty());
  assert(query_resp.getServerName().empty());

  std::cout << "ResponseParser Query empty-payload test passed" << std::endl;
}


void test_key_parser_symmetric() {
  // Construct a mock GetResponse with Symmetric Key
  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "key-id")
  );
  payload->asStructure()->add(
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
  key_block->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, KMIP_CRYPTOALG_AES
      )
  );

  auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
  std::vector<uint8_t> actual_key = {0xDE, 0xAD, 0xBE, 0xEF};
  key_value->asStructure()->add(
      Element::createByteString(tag::KMIP_TAG_KEY_MATERIAL, actual_key)
  );

  key_block->asStructure()->add(key_value);
  symmetric_key->asStructure()->add(key_block);
  payload->asStructure()->add(symmetric_key);

  ResponseBatchItem item;
  item.setOperation(KMIP_OP_GET);
  item.setResultStatus(KMIP_STATUS_SUCCESS);
  item.setResponsePayload(payload);

  GetResponseBatchItem get_resp = GetResponseBatchItem::fromBatchItem(item);
  Key key = KeyParser::parseGetKeyResponse(get_resp);

  assert(
      key.attributes().algorithm() ==
      cryptographic_algorithm::KMIP_CRYPTOALG_AES
  );
  assert(key.value() == actual_key);

  std::cout << "KeyParser Symmetric Key test passed" << std::endl;
}

void test_key_parser_secret_binary() {
  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "secret-id")
  );
  payload->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SECRET_DATA
      )
  );

  auto secret_data = Element::createStructure(tag::KMIP_TAG_SECRET_DATA);
  secret_data->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_SECRET_DATA_TYPE,
          static_cast<int32_t>(secret_data_type::KMIP_SECDATA_PASSWORD)
      )
  );

  auto key_block = Element::createStructure(tag::KMIP_TAG_KEY_BLOCK);
  key_block->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_KEY_FORMAT_TYPE, KMIP_KEYFORMAT_OPAQUE
      )
  );

  auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
  const std::vector<unsigned char> bytes = {'p', 'a', 's', 's', 0x00, 'x'};
  key_value->asStructure()->add(
      Element::createByteString(
          tag::KMIP_TAG_KEY_MATERIAL,
          std::vector<uint8_t>(bytes.begin(), bytes.end())
      )
  );
  key_block->asStructure()->add(key_value);
  secret_data->asStructure()->add(key_block);
  payload->asStructure()->add(secret_data);

  ResponseBatchItem item;
  item.setOperation(KMIP_OP_GET);
  item.setResultStatus(KMIP_STATUS_SUCCESS);
  item.setResponsePayload(payload);

  GetResponseBatchItem get_resp = GetResponseBatchItem::fromBatchItem(item);
  auto secret = KeyParser::parseGetSecretResponse(get_resp);

  assert(secret.get_state() == state::KMIP_STATE_PRE_ACTIVE);
  assert(secret.value() == bytes);
  assert(secret.get_state() == state::KMIP_STATE_PRE_ACTIVE);
  assert(secret.as_text().size() == bytes.size());

  std::cout << "KeyParser Secret Binary test passed" << std::endl;
}

// Builds a Get response payload for a Secret Data object whose Secret Data
// Type is @p secret_type.
std::shared_ptr<Element> make_secret_payload(int32_t secret_type) {
  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "secret-id")
  );
  payload->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SECRET_DATA
      )
  );

  auto secret_data = Element::createStructure(tag::KMIP_TAG_SECRET_DATA);
  secret_data->asStructure()->add(
      Element::createEnumeration(tag::KMIP_TAG_SECRET_DATA_TYPE, secret_type)
  );

  auto key_block = Element::createStructure(tag::KMIP_TAG_KEY_BLOCK);
  key_block->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_KEY_FORMAT_TYPE, KMIP_KEYFORMAT_OPAQUE
      )
  );
  auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
  key_value->asStructure()->add(
      Element::createByteString(
          tag::KMIP_TAG_KEY_MATERIAL, std::vector<uint8_t>{'p', 'w'}
      )
  );
  key_block->asStructure()->add(key_value);
  secret_data->asStructure()->add(key_block);
  payload->asStructure()->add(secret_data);
  return payload;
}

Secret parse_secret_payload(const std::shared_ptr<Element> &payload) {
  ResponseBatchItem item;
  item.setOperation(KMIP_OP_GET);
  item.setResultStatus(KMIP_STATUS_SUCCESS);
  item.setResponsePayload(payload);

  GetResponseBatchItem get_resp = GetResponseBatchItem::fromBatchItem(item);
  return KeyParser::parseGetSecretResponse(get_resp);
}

void test_key_parser_rejects_out_of_range_secret_type() {
  // An attacker-controlled Secret Data Type enumeration that is neither a
  // defined value nor in the Extensions range must be rejected rather than
  // cast into the scoped enum (KMIP 1.4 §9.1.3.2.9, KMIP 2.0 §11.50).
  for (const uint32_t raw :
       {0x00000000u,
        0x00000003u,
        0x0000007Fu,
        0x7FFFFFFFu,
        0x90000000u,
        0xFFFFFFFFu}) {
    bool threw = false;
    try {
      (void) parse_secret_payload(
          make_secret_payload(static_cast<int32_t>(raw))
      );
    } catch (const KmipException &) {
      threw = true;
    }
    assert(threw);
  }

  std::cout << "KeyParser out-of-range secret type rejection test passed"
            << std::endl;
}

void test_key_parser_accepts_extension_secret_type() {
  // Secret Data Type values with 8 hex in the first nibble are Extensions
  // (KMIP 1.4 §9.1.1.4, §9.1.3.2.9; KMIP 2.0 §11.50) and must be accepted.
  for (const uint32_t raw : {0x80000000u, 0x80000001u, 0x8FFFFFFFu}) {
    auto secret =
        parse_secret_payload(make_secret_payload(static_cast<int32_t>(raw)));
    assert(static_cast<uint32_t>(secret.get_secret_type()) == raw);
    assert(secret.value() == std::vector<unsigned char>({'p', 'w'}));
  }

  std::cout << "KeyParser extension secret type acceptance test passed"
            << std::endl;
}

// Cryptographic Algorithm and Length go out as a pair or not at all (KMIP
// 1.4 §2.1.3 Table 7, 2.0 §3.1), in the Key Block and in Register's
// attributes alike.
void test_register_key_request_algorithm_and_length() {
  struct Sent {
    std::optional<int32_t> block_algorithm, block_length;
    std::optional<int32_t> attr_algorithm, attr_length;
  };
  auto sent = [](const Key &key, ProtocolVersion version) {
    RegisterKeyRequest req("k-name", "k-group", key, version);
    const auto payload = req.getRequestPayload();
    const auto value_of = [](const std::shared_ptr<Element> &e) {
      return e ? std::optional<int32_t>(e->toInt()) : std::nullopt;
    };
    const auto enum_of = [](const std::shared_ptr<Element> &e) {
      return e ? std::optional<int32_t>(e->toEnum()) : std::nullopt;
    };
    Sent out;
    for (const auto object_tag :
         {tag::KMIP_TAG_SYMMETRIC_KEY,
          tag::KMIP_TAG_PRIVATE_KEY,
          tag::KMIP_TAG_PUBLIC_KEY}) {
      if (const auto object = payload->getChild(object_tag)) {
        const auto block = object->getChild(tag::KMIP_TAG_KEY_BLOCK);
        out.block_algorithm =
            enum_of(block->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM));
        out.block_length =
            value_of(block->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH));
      }
    }
    if (version.is_at_least(2, 0)) {
      const auto attrs = payload->getChild(tag::KMIP_TAG_ATTRIBUTES);
      out.attr_algorithm =
          enum_of(attrs->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM));
      out.attr_length =
          value_of(attrs->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH));
    } else {
      const auto tmpl = payload->getChild(tag::KMIP_TAG_TEMPLATE_ATTRIBUTE);
      for (const auto &attr : tmpl->getChildren(tag::KMIP_TAG_ATTRIBUTE)) {
        const auto name =
            attr->getChild(tag::KMIP_TAG_ATTRIBUTE_NAME)->toString();
        const auto value = attr->getChild(tag::KMIP_TAG_ATTRIBUTE_VALUE);
        if (name == "Cryptographic Algorithm") {
          out.attr_algorithm = value->toEnum();
        } else if (name == "Cryptographic Length") {
          out.attr_length = value->toInt();
        }
      }
    }
    return out;
  };
  auto expect_pair = [](const Sent &s,
                        std::optional<int32_t> algorithm,
                        std::optional<int32_t> length) {
    assert(s.block_algorithm == algorithm && s.attr_algorithm == algorithm);
    assert(s.block_length == length && s.attr_length == length);
  };
  auto with = [](cryptographic_algorithm algorithm,
                 std::optional<int32_t> length) {
    Attributes attrs;
    attrs.set_algorithm(algorithm);
    if (length) {
      attrs.set_crypto_length(*length);
    }
    return attrs;
  };
  const std::vector<unsigned char> der(121, 0x30);
  const ProtocolVersion v14(1, 4);
  const ProtocolVersion v20(2, 0);
  constexpr auto kRsa = static_cast<int32_t>(KMIP_CRYPTOALG_RSA);
  constexpr auto kAes = static_cast<int32_t>(KMIP_CRYPTOALG_AES);
  constexpr auto kEd25519 = static_cast<int32_t>(KMIP_CRYPTOALG_ED25519);

  for (const auto &version : {v14, v20}) {
    // Both known: sent.
    expect_pair(
        sent(
            Key(der,
                KeyType::PRIVATE_KEY,
                with(cryptographic_algorithm::KMIP_CRYPTOALG_RSA, 2048)),
            version
        ),
        kRsa,
        2048
    );
    // An asymmetric key's value size is not its length (it is the size of
    // the encoding), so with no length set neither is sent.
    expect_pair(
        sent(
            Key(
                der,
                KeyType::PUBLIC_KEY,
                with(cryptographic_algorithm::KMIP_CRYPTOALG_RSA, std::nullopt)
            ),
            version
        ),
        std::nullopt,
        std::nullopt
    );
    expect_pair(
        sent(Key(der, KeyType::PRIVATE_KEY), version),
        std::nullopt,
        std::nullopt
    );
    // A Raw symmetric key's size is its length.
    expect_pair(
        sent(
            Key(
                std::vector<unsigned char>(16, 1),
                KeyType::SYMMETRIC_KEY,
                with(cryptographic_algorithm::KMIP_CRYPTOALG_AES, std::nullopt)
            ),
            version
        ),
        kAes,
        128
    );
  }

  // A Raw symmetric key does not carry its algorithm, so a Key Block
  // without one would break the rule above: Register refuses it, also for
  // an algorithm the request's KMIP version does not define.
  // The message Register throws with for a symmetric key, or "" if none.
  const auto register_error = [](const Key &key, ProtocolVersion version) {
    try {
      RegisterKeyRequest req("k-name", "k-group", key, version);
    } catch (const KmipException &e) {
      assert(e.code().value() == KMIP_INVALID_FIELD);
      return std::string(e.what());
    }
    return std::string();
  };
  const auto mentions = [](const std::string &message, const char *part) {
    return message.find(part) != std::string::npos;
  };
  const std::vector<unsigned char> raw(16, 1);
  for (const auto &version : {v14, v20}) {
    assert(mentions(
        register_error(Key(raw, KeyType::SYMMETRIC_KEY), version),
        "without a Cryptographic Algorithm"
    ));
    // The algorithm is there; what is missing is a length.
    assert(mentions(
        register_error(
            Key(
                std::vector<unsigned char>{},
                KeyType::SYMMETRIC_KEY,
                with(cryptographic_algorithm::KMIP_CRYPTOALG_AES, std::nullopt)
            ),
            version
        ),
        "without a Cryptographic Length"
    ));
    // A length that is set but not positive is named as such.
    for (const int32_t length : {0, -8}) {
      assert(mentions(
          register_error(
              Key(raw,
                  KeyType::SYMMETRIC_KEY,
                  with(cryptographic_algorithm::KMIP_CRYPTOALG_AES, length)),
              version
          ),
          "it must be positive"
      ));
    }
  }
  const Key aria(
      raw,
      KeyType::SYMMETRIC_KEY,
      with(cryptographic_algorithm::KMIP_CRYPTOALG_ARIA, std::nullopt)
  );
  assert(mentions(register_error(aria, v14), "KMIP 1.4 does not define"));
  assert(register_error(aria, v20).empty());  // ARIA is KMIP 2.0 only

  // Each 1.x version's own algorithm list: One Time Pad came in 1.3, so a
  // 1.2 request must not send it (see last_crypto_algorithm()).
  const Key one_time_pad(
      raw,
      KeyType::SYMMETRIC_KEY,
      with(cryptographic_algorithm::KMIP_CRYPTOALG_ONE_TIME_PAD, std::nullopt)
  );
  assert(mentions(
      register_error(one_time_pad, ProtocolVersion(1, 2)),
      "KMIP 1.2 does not define"
  ));
  assert(register_error(one_time_pad, ProtocolVersion(1, 3)).empty());

  // Ed25519 exists only in KMIP 2.0 (2.0 §11.12).
  const Key ed25519(
      der,
      KeyType::PRIVATE_KEY,
      with(cryptographic_algorithm::KMIP_CRYPTOALG_ED25519, 256)
  );
  expect_pair(sent(ed25519, v14), std::nullopt, std::nullopt);
  expect_pair(sent(ed25519, v20), kEd25519, 256);

  // Extensions values (8XXXXXXX, 1.4 §9.1.1.4, 2.0 §10.1.2) are permitted
  // in every version, so a vendor algorithm read back from the server goes
  // back unchanged. Codes above the version's last defined one, including
  // 0x90000000 and up, which are neither defined nor extensions, are not.
  for (const auto &version : {ProtocolVersion(1, 0), v14, v20}) {
    for (const uint32_t code : {0x80000000u, 0x80000001u, 0x8FFFFFFFu}) {
      const Key vendor(
          raw,
          KeyType::SYMMETRIC_KEY,
          with(static_cast<cryptographic_algorithm>(code), std::nullopt)
      );
      expect_pair(sent(vendor, version), static_cast<int32_t>(code), 128);
    }
    for (const uint32_t code : {0x00000039u, 0x7FFFFFFFu, 0x90000000u}) {
      const Key undefined(
          raw,
          KeyType::SYMMETRIC_KEY,
          with(static_cast<cryptographic_algorithm>(code), std::nullopt)
      );
      assert(mentions(
          register_error(undefined, version),
          (std::to_string(code) + ", which KMIP").c_str()
      ));
    }
  }

  std::cout << "RegisterKeyRequest algorithm/length pairing test passed"
            << std::endl;
}

void test_get_request_key_format_type() {
  // No Key Format Type unless asked for: the server picks its default.
  const auto plain = GetRequest("id-1").getRequestPayload();
  assert(plain->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE) == nullptr);

  const auto pkcs8 =
      GetRequest("id-1", KMIP_KEYFORMAT_PKCS8).getRequestPayload();
  auto format = pkcs8->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE);
  assert(format != nullptr && format->toEnum() == KMIP_KEYFORMAT_PKCS8);
  assert(
      pkcs8->getChild(tag::KMIP_TAG_UNIQUE_IDENTIFIER)->toString() == "id-1"
  );

  std::cout << "GetRequest Key Format Type test passed" << std::endl;
}

void test_key_parser_key_format_type() {
  auto get_response_with = [](std::shared_ptr<Element> object, int32_t type) {
    auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
    payload->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_OBJECT_TYPE, type)
    );
    payload->asStructure()->add(
        Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "id-1")
    );
    payload->asStructure()->add(object);
    ResponseBatchItem item;
    item.setOperation(KMIP_OP_GET);
    item.setResultStatus(KMIP_STATUS_SUCCESS);
    item.setResponsePayload(payload);
    return GetResponseBatchItem::fromBatchItem(item);
  };

  // A private key in the given format, with byte or structure material.
  auto private_key_in = [](int32_t format, bool structure_material) {
    auto material =
        structure_material
            ? Element::createStructure(tag::KMIP_TAG_KEY_MATERIAL)
            : Element::createByteString(
                  tag::KMIP_TAG_KEY_MATERIAL, std::vector<uint8_t>(8, 0x30)
              );
    auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
    key_value->asStructure()->add(material);
    auto key_block = Element::createStructure(tag::KMIP_TAG_KEY_BLOCK);
    key_block->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_KEY_FORMAT_TYPE, format)
    );
    key_block->asStructure()->add(key_value);
    auto private_key = Element::createStructure(tag::KMIP_TAG_PRIVATE_KEY);
    private_key->asStructure()->add(key_block);
    return private_key;
  };

  const auto pkcs1 = get_response_with(
      private_key_in(KMIP_KEYFORMAT_PKCS1, false), KMIP_OBJTYPE_PRIVATE_KEY
  );
  assert(KeyParser::keyFormatType(pkcs1) == KMIP_KEYFORMAT_PKCS1);
  // The parsed key records the format of its bytes.
  assert(
      KeyParser::parseGetKeyResponse(pkcs1).key_format() ==
      static_cast<int32_t>(KMIP_KEYFORMAT_PKCS1)
  );

  // Transparent formats hold a structure, which is reported, not
  // misread as bytes.
  const auto transparent = get_response_with(
      private_key_in(KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY, true),
      KMIP_OBJTYPE_PRIVATE_KEY
  );
  bool threw = false;
  try {
    (void) KeyParser::parseGetKeyResponse(transparent);
  } catch (const KmipException &e) {
    threw = e.code().value() == KMIP_NOT_IMPLEMENTED;
  }
  assert(threw);

  // No Key Block, no Key Format Type.
  auto bare_key = Element::createStructure(tag::KMIP_TAG_PRIVATE_KEY);
  assert(!KeyParser::keyFormatType(
              get_response_with(bare_key, KMIP_OBJTYPE_PRIVATE_KEY)
  )
              .has_value());

  std::cout << "KeyParser::keyFormatType test passed" << std::endl;
}

// Register declares the value's recorded Key Format Type, else the default
// of its type.
void test_register_key_request_key_format() {
  auto declared = [](const Key &key, Tag object_tag) {
    RegisterKeyRequest req("k-name", "k-group", key);
    return req.getRequestPayload()
        ->getChild(object_tag)
        ->getChild(tag::KMIP_TAG_KEY_BLOCK)
        ->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE)
        ->toEnum();
  };
  const std::vector<unsigned char> der(121, 0x30);
  assert(
      declared(Key(der, KeyType::PRIVATE_KEY), tag::KMIP_TAG_PRIVATE_KEY) ==
      static_cast<int32_t>(KMIP_KEYFORMAT_PKCS8)
  );
  assert(
      declared(Key(der, KeyType::PUBLIC_KEY), tag::KMIP_TAG_PUBLIC_KEY) ==
      static_cast<int32_t>(KMIP_KEYFORMAT_X509)
  );
  Key pkcs1(der, KeyType::PRIVATE_KEY);
  pkcs1.set_key_format(KMIP_KEYFORMAT_PKCS1);
  assert(
      declared(pkcs1, tag::KMIP_TAG_PRIVATE_KEY) ==
      static_cast<int32_t>(KMIP_KEYFORMAT_PKCS1)
  );
  std::cout << "RegisterKeyRequest Key Format Type test passed" << std::endl;
}

void test_register_secret_request_structure() {
  const std::vector<unsigned char> secret = {'a', 'b', 0x00, 'c'};
  RegisterSecretRequest req(
      "s-name", "s-group", secret, secret_data_type::KMIP_SECDATA_PASSWORD
  );

  auto payload = req.getRequestPayload();
  assert(payload != nullptr);

  auto object_type = payload->getChild(tag::KMIP_TAG_OBJECT_TYPE);
  assert(object_type != nullptr);
  assert(object_type->toEnum() == KMIP_OBJTYPE_SECRET_DATA);

  auto secret_data = payload->getChild(tag::KMIP_TAG_SECRET_DATA);
  assert(secret_data != nullptr);

  auto secret_type = secret_data->getChild(tag::KMIP_TAG_SECRET_DATA_TYPE);
  assert(secret_type != nullptr);
  assert(
      static_cast<secret_data_type>(secret_type->toEnum()) ==
      secret_data_type::KMIP_SECDATA_PASSWORD
  );

  auto key_block = secret_data->getChild(tag::KMIP_TAG_KEY_BLOCK);
  assert(key_block != nullptr);

  auto key_format = key_block->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE);
  assert(key_format != nullptr);
  assert(key_format->toEnum() == KMIP_KEYFORMAT_OPAQUE);

  // KMIP 1.4: Secret Data Key Block does not require algorithm/length.
  assert(key_block->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM) == nullptr);
  assert(key_block->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH) == nullptr);

  auto key_value = key_block->getChild(tag::KMIP_TAG_KEY_VALUE);
  assert(key_value != nullptr);
  auto key_material = key_value->getChild(tag::KMIP_TAG_KEY_MATERIAL);
  assert(key_material != nullptr);
  auto parsed = key_material->toBytes();
  assert(parsed.size() == secret.size());
  assert(std::equal(parsed.begin(), parsed.end(), secret.begin()));

  std::cout << "RegisterSecretRequest structure test passed" << std::endl;
}

void test_attributes_parser() {
  std::vector<std::shared_ptr<Element>> attributes;

  auto attr1 = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  attr1->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "Name")
  );
  attr1->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_VALUE, "MyKey")
  );
  attributes.push_back(attr1);

  auto attr2 = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  attr2->asStructure()->add(
      Element::createTextString(
          tag::KMIP_TAG_ATTRIBUTE_NAME, "Cryptographic Length"
      )
  );
  attr2->asStructure()->add(
      Element::createInteger(tag::KMIP_TAG_ATTRIBUTE_VALUE, 256)
  );
  attributes.push_back(attr2);

  auto parsed_attrs = AttributesParser::parse(attributes);

  assert(parsed_attrs.has_attribute("Name"));
  assert(parsed_attrs.get("Name") == "MyKey");

  // Cryptographic Length is now stored as a typed field.
  assert(parsed_attrs.crypto_length().has_value());
  assert(parsed_attrs.crypto_length().value() == 256);

  std::cout << "AttributesParser test passed" << std::endl;
}

void test_attributes_parser_extended() {
  std::vector<std::shared_ptr<Element>> attributes;

  // Test Date attribute
  auto attr_date = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  attr_date->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "Activation Date")
  );
  attr_date->asStructure()->add(
      Element::createDateTime(tag::KMIP_TAG_ATTRIBUTE_VALUE, 1678886400)
  );  // 2023-03-15T13:20:00Z (approx)
  attributes.push_back(attr_date);

  // Test Crypto Algorithm Enum
  auto attr_alg = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  attr_alg->asStructure()->add(
      Element::createTextString(
          tag::KMIP_TAG_ATTRIBUTE_NAME, "Cryptographic Algorithm"
      )
  );
  attr_alg->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_ATTRIBUTE_VALUE, KMIP_CRYPTOALG_AES
      )
  );
  attributes.push_back(attr_alg);

  auto parsed_attrs = AttributesParser::parse(attributes);

  assert(parsed_attrs.has_attribute("Activation Date"));
  const auto &date_str = parsed_attrs.get("Activation Date");
  assert(date_str.find("2023-03-15") != std::string::npos);

  // Cryptographic Algorithm is now a typed field.
  assert(
      parsed_attrs.algorithm() == cryptographic_algorithm::KMIP_CRYPTOALG_AES
  );

  std::cout << "AttributesParser Extended test passed" << std::endl;
}

void test_attributes_parser_v2_typed() {
  // KMIP 2.0 response attributes: typed elements, no Attribute name/value
  // wrappers.
  std::vector<std::shared_ptr<Element>> v2_attrs;

  // Cryptographic Algorithm (Enumeration with specific tag)
  v2_attrs.push_back(
      Element::createEnumeration(
          tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, KMIP_CRYPTOALG_AES
      )
  );
  // Cryptographic Length (Integer with specific tag)
  v2_attrs.push_back(
      Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, 256)
  );
  // Cryptographic Usage Mask (Integer with specific tag)
  v2_attrs.push_back(
      Element::createInteger(
          tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK,
          KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT
      )
  );
  // State (Enumeration with specific tag)
  v2_attrs.push_back(
      Element::createEnumeration(
          tag::KMIP_TAG_STATE, static_cast<int32_t>(state::KMIP_STATE_ACTIVE)
      )
  );
  // Name (Structure with Name Value + Name Type)
  {
    auto name_elem = Element::createStructure(tag::KMIP_TAG_NAME);
    name_elem->asStructure()->add(
        Element::createTextString(tag::KMIP_TAG_NAME_VALUE, "TestKey2")
    );
    name_elem->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_NAME_TYPE, KMIP_NAME_UNINTERPRETED_TEXT_STRING
        )
    );
    v2_attrs.push_back(name_elem);
  }
  // Object Group (Text String with specific tag)
  v2_attrs.push_back(
      Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, "production")
  );
  // Unknown typed attribute should be preserved in generic form.
  v2_attrs.push_back(
      Element::createInteger(tag::KMIP_TAG_APPLICATION_NAMESPACE, 3600)
  );

  auto result = AttributesParser::parse(v2_attrs);

  assert(result.algorithm() == cryptographic_algorithm::KMIP_CRYPTOALG_AES);
  assert(result.crypto_length().has_value());
  assert(result.crypto_length().value() == 256);
  assert(
      result.usage_mask() ==
      static_cast<cryptographic_usage_mask>(
          KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT
      )
  );
  assert(result.object_state() == state::KMIP_STATE_ACTIVE);
  assert(result.has_attribute("Name"));
  assert(result.get("Name") == "TestKey2");
  assert(result.has_attribute("Object Group"));
  assert(result.get("Object Group") == "production");
  assert(result.has_attribute("Tag(0x420003)"));
  assert(result.get_int("Tag(0x420003)").has_value());
  assert(result.get_int("Tag(0x420003)").value() == 3600);

  std::cout << "AttributesParser KMIP 2.0 typed attributes test passed"
            << std::endl;
}

// Wraps @p value in a KMIP 1.x Attribute structure named @p name.
std::shared_ptr<Element> make_legacy_attribute(
    const std::string &name, const std::shared_ptr<Element> &value
) {
  auto attr = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  attr->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, name)
  );
  attr->asStructure()->add(value);
  return attr;
}

Attributes parse_single_attribute(const std::shared_ptr<Element> &attr) {
  std::vector<std::shared_ptr<Element>> attrs{attr};
  return AttributesParser::parse(attrs);
}

void test_attributes_parser_rejects_out_of_range_enums() {
  // A malicious server can send any 4-byte Enumeration. Security-relevant
  // attributes (algorithm, state) must be validated against the KMIP value
  // tables before being cast into the scoped enums that steer key-handling
  // decisions. Values outside both the defined codes and the Extensions range
  // (8 hex in the first nibble, KMIP 1.4 §9.1.1.4) are rejected.
  auto expect_throws = [](const std::shared_ptr<Element> &attr) {
    bool threw = false;
    try {
      (void) parse_single_attribute(attr);
    } catch (const KmipException &) {
      threw = true;
    }
    assert(threw);
  };

  // 0 is not a defined code and 0x39 is one past Ed448 = 0x38; 0x7FFFFFFF
  // and 0x90000000 are just outside the Extensions range on either side.
  for (const uint32_t raw :
       {0x00000000u, 0x00000039u, 0x7FFFFFFFu, 0x90000000u, 0xFFFFFFFFu}) {
    const auto v = static_cast<int32_t>(raw);
    expect_throws(
        Element::createEnumeration(tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, v)
    );
    // Same validation on the KMIP 1.x Attribute name/value wrapper path.
    expect_throws(make_legacy_attribute(
        "Cryptographic Algorithm",
        Element::createEnumeration(tag::KMIP_TAG_ATTRIBUTE_VALUE, v)
    ));
  }

  // Lifecycle state: defined range is 0x01..0x06.
  for (const uint32_t raw :
       {0x00000000u, 0x00000007u, 0x7FFFFFFFu, 0x90000000u, 0xFFFFFFFFu}) {
    const auto v = static_cast<int32_t>(raw);
    expect_throws(Element::createEnumeration(tag::KMIP_TAG_STATE, v));
    expect_throws(make_legacy_attribute(
        "State", Element::createEnumeration(tag::KMIP_TAG_ATTRIBUTE_VALUE, v)
    ));
  }

  std::cout << "AttributesParser out-of-range enum rejection test passed"
            << std::endl;
}

void test_attributes_parser_accepts_extension_values() {
  // Objects stored by other software may use vendor extensions. Algorithm and
  // State values in the Extensions range (KMIP 1.4 §9.1.3.2.13, §9.1.3.2.18;
  // KMIP 2.0 §11.12, §11.53) must be accepted, at both ends of the range and
  // inside it.
  for (const uint32_t raw : {0x80000000u, 0x80000001u, 0x8FFFFFFFu}) {
    const auto v = static_cast<int32_t>(raw);

    auto alg = parse_single_attribute(
        Element::createEnumeration(tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, v)
    );
    assert(static_cast<uint32_t>(alg.algorithm()) == raw);
    alg = parse_single_attribute(make_legacy_attribute(
        "Cryptographic Algorithm",
        Element::createEnumeration(tag::KMIP_TAG_ATTRIBUTE_VALUE, v)
    ));
    assert(static_cast<uint32_t>(alg.algorithm()) == raw);

    auto st = parse_single_attribute(
        Element::createEnumeration(tag::KMIP_TAG_STATE, v)
    );
    assert(static_cast<uint32_t>(st.object_state()) == raw);
    st = parse_single_attribute(make_legacy_attribute(
        "State", Element::createEnumeration(tag::KMIP_TAG_ATTRIBUTE_VALUE, v)
    ));
    assert(static_cast<uint32_t>(st.object_state()) == raw);

    // An extension State has no name: as_string_map() gives its number,
    // which Attributes::set() reads back.
    const auto as_string =
        st.as_string_map().at(std::string(KMIP_ATTR_NAME_STATE));
    assert(as_string == std::to_string(raw));
    Attributes copy;
    copy.set(KMIP_ATTR_NAME_STATE, as_string);
    assert(copy.object_state() == st.object_state());
  }

  // Every Cryptographic Usage Mask bit is either a defined flag or reserved
  // for extensions (KMIP 1.4 §9.1.3.3.1, KMIP 2.0 §12.1: Extensions
  // XXX00000), so any mask is accepted and kept as sent.
  for (const uint32_t raw :
       {0x0000000Cu,
        0x00100000u,
        0x00800000u,
        0x0100000Cu,
        0x80000000u,
        0xFFFFFFFFu}) {
    const auto v = static_cast<int32_t>(raw);
    auto mask = parse_single_attribute(
        Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK, v)
    );
    assert(static_cast<uint32_t>(mask.usage_mask()) == raw);
    mask = parse_single_attribute(make_legacy_attribute(
        "Cryptographic Usage Mask",
        Element::createInteger(tag::KMIP_TAG_ATTRIBUTE_VALUE, v)
    ));
    assert(static_cast<uint32_t>(mask.usage_mask()) == raw);
  }

  std::cout << "AttributesParser extension value acceptance test passed"
            << std::endl;
}

void test_attributes_parser_legacy_wrapper_preserves_generic_types() {
  std::vector<std::shared_ptr<Element>> attributes;

  auto bool_attr = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  bool_attr->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "Custom Bool")
  );
  bool_attr->asStructure()->add(
      Element::createBoolean(tag::KMIP_TAG_ATTRIBUTE_VALUE, true)
  );
  attributes.push_back(bool_attr);

  auto bytes_attr = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  bytes_attr->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "Custom Bytes")
  );
  bytes_attr->asStructure()->add(
      Element::createByteString(
          tag::KMIP_TAG_ATTRIBUTE_VALUE,
          std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}
      )
  );
  attributes.push_back(bytes_attr);

  auto interval_attr = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  interval_attr->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "Custom Interval")
  );
  interval_attr->asStructure()->add(
      Element::createInterval(tag::KMIP_TAG_ATTRIBUTE_VALUE, 3600)
  );
  attributes.push_back(interval_attr);

  auto dt_ext_attr = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
  dt_ext_attr->asStructure()->add(
      Element::createTextString(
          tag::KMIP_TAG_ATTRIBUTE_NAME, "Custom DateTimeExtended"
      )
  );
  dt_ext_attr->asStructure()->add(
      Element::createDateTimeExtended(
          tag::KMIP_TAG_ATTRIBUTE_VALUE, 1700000000123456LL
      )
  );
  attributes.push_back(dt_ext_attr);

  auto parsed = AttributesParser::parse(attributes);

  assert(parsed.has_attribute("Custom Bool"));
  assert(parsed.get_as_string("Custom Bool").has_value());
  assert(parsed.get_as_string("Custom Bool").value() == "true");

  assert(parsed.has_attribute("Custom Bytes"));
  assert(parsed.get("Custom Bytes") == "DE AD BE EF");

  assert(parsed.has_attribute("Custom Interval"));
  assert(parsed.get_long("Custom Interval").has_value());
  assert(parsed.get_long("Custom Interval").value() == 3600);

  assert(parsed.has_attribute("Custom DateTimeExtended"));
  assert(parsed.get_long("Custom DateTimeExtended").has_value());
  assert(
      parsed.get_long("Custom DateTimeExtended").value() == 1700000000123456LL
  );

  std::cout
      << "AttributesParser legacy wrapper generic-type preservation test passed"
      << std::endl;
}

void test_get_attributes_request_encodes_per_protocol_version() {
  const std::vector<std::string> attrs = {
      std::string(KMIP_ATTR_NAME_STATE),
      std::string(KMIP_ATTR_NAME_CRYPTO_ALG),
      "Vendor Custom Attr"
  };

  // KMIP 1.4: selectors are repeated Attribute Name text strings.
  {
    GetAttributesRequest req("id-1", attrs, ProtocolVersion(1, 4));
    auto payload = req.getRequestPayload();
    assert(payload != nullptr);
    assert(
        payload->getChildren(tag::KMIP_TAG_ATTRIBUTE_NAME).size() ==
        attrs.size()
    );
    assert(payload->getChildren(tag::KMIP_TAG_ATTRIBUTE_REFERENCE).empty());
  }

  // KMIP 2.0: selectors are Attribute Reference structures.
  {
    GetAttributesRequest req("id-1", attrs, ProtocolVersion(2, 0));
    auto payload = req.getRequestPayload();
    assert(payload != nullptr);
    assert(payload->getChildren(tag::KMIP_TAG_ATTRIBUTE_NAME).empty());
    const auto refs = payload->getChildren(tag::KMIP_TAG_ATTRIBUTE_REFERENCE);
    assert(refs.size() == attrs.size());
    // Standard attrs are encoded as Attribute Reference enum children.
    assert(refs[0]->getChild(tag::KMIP_TAG_ATTRIBUTE_REFERENCE) != nullptr);
    assert(refs[1]->getChild(tag::KMIP_TAG_ATTRIBUTE_REFERENCE) != nullptr);
    // Vendor-defined attrs are encoded by name.
    assert(refs[2]->getChild(tag::KMIP_TAG_ATTRIBUTE_NAME) != nullptr);
    assert(
        refs[2]->getChild(tag::KMIP_TAG_ATTRIBUTE_NAME)->toString() ==
        "Vendor Custom Attr"
    );
  }

  // Empty attribute list means "return all" in both versions.
  for (const auto &ver : {ProtocolVersion(1, 4), ProtocolVersion(2, 0)}) {
    GetAttributesRequest req_empty("id-1", {}, ver);
    auto payload = req_empty.getRequestPayload();
    assert(payload != nullptr);
    assert(payload->getChildren(tag::KMIP_TAG_ATTRIBUTE_NAME).empty());
    assert(payload->getChildren(tag::KMIP_TAG_ATTRIBUTE_REFERENCE).empty());
  }

  std::cout << "GetAttributesRequest version-aware encoding test passed"
            << std::endl;
}

void test_get_attribute_list_response_supports_v2_attribute_reference() {
  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "id-1")
  );

  auto state_ref = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE_REFERENCE);
  state_ref->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_ATTRIBUTE_REFERENCE, KMIP_TAG_STATE
      )
  );
  payload->asStructure()->add(state_ref);

  auto custom_ref = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE_REFERENCE);
  custom_ref->asStructure()->add(
      Element::createTextString(
          tag::KMIP_TAG_ATTRIBUTE_NAME, "Vendor Custom Attr"
      )
  );
  payload->asStructure()->add(custom_ref);

  auto bytes = create_mock_response_bytes(KMIP_OP_GET_ATTRIBUTE_LIST, payload);
  ResponseParser parser(bytes);
  auto response = parser.getResponse<GetAttributeListResponseBatchItem>(0);

  const auto &names = response.getAttributeNames();
  assert(names.size() == 2);
  assert(names[0] == KMIP_ATTR_NAME_STATE);
  assert(names[1] == "Vendor Custom Attr");

  std::cout
      << "GetAttributeListResponse KMIP 2.0 Attribute Reference test passed"
      << std::endl;
}

void test_formatter_for_request_and_response() {
  RequestMessage request;
  request.add_batch_item(GetRequest("request-id-123"));

  auto formatted_request = format_request(request);
  assert(formatted_request.find("RequestMessage") != std::string::npos);
  assert(formatted_request.find("Operation") != std::string::npos);
  assert(formatted_request.find("Get") != std::string::npos);
  assert(formatted_request.find("request-id-123") != std::string::npos);

  auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  payload->asStructure()->add(
      Element::createInteger(tag::KMIP_TAG_LOCATED_ITEMS, 2)
  );
  payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "uuid-1")
  );
  payload->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "uuid-2")
  );

  auto bytes = create_mock_response_bytes(KMIP_OP_LOCATE, payload);
  auto formatted_response = format_ttlv(bytes);
  assert(formatted_response.find("ResponseMessage") != std::string::npos);
  assert(formatted_response.find("Locate") != std::string::npos);
  assert(formatted_response.find("uuid-1") != std::string::npos);
  assert(formatted_response.find("uuid-2") != std::string::npos);

  std::cout << "KMIP formatter test passed" << std::endl;
}

void test_formatter_redacts_sensitive_fields() {
  auto root = Element::createStructure(tag::KMIP_TAG_REQUEST_MESSAGE);
  root->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_USERNAME, "alice")
  );
  root->asStructure()->add(
      Element::createTextString(tag::KMIP_TAG_PASSWORD, "s3cr3t")
  );
  root->asStructure()->add(
      Element::createByteString(
          tag::KMIP_TAG_KEY_MATERIAL, {0xDE, 0xAD, 0xBE, 0xEF}
      )
  );

  auto secret_data = Element::createStructure(tag::KMIP_TAG_SECRET_DATA);
  secret_data->asStructure()->add(
      Element::createEnumeration(
          tag::KMIP_TAG_SECRET_DATA_TYPE,
          static_cast<int32_t>(secret_data_type::KMIP_SECDATA_PASSWORD)
      )
  );
  root->asStructure()->add(secret_data);

  const auto formatted = format_element(root);
  assert(formatted.find("Username") != std::string::npos);
  assert(formatted.find("Password") != std::string::npos);
  assert(formatted.find("KeyMaterial") != std::string::npos);
  assert(formatted.find("SecretData") != std::string::npos);
  assert(formatted.find("<redacted sensitive") != std::string::npos);
  assert(formatted.find("alice") == std::string::npos);
  assert(formatted.find("s3cr3t") == std::string::npos);
  assert(formatted.find("DE AD BE EF") == std::string::npos);

  std::cout << "KMIP formatter redaction test passed" << std::endl;
}

void test_formatter_parse_failure_omits_raw_bytes() {
  const std::vector<uint8_t> malformed = {
      static_cast<uint8_t>('s'),
      static_cast<uint8_t>('3'),
      static_cast<uint8_t>('c'),
      static_cast<uint8_t>('r'),
      static_cast<uint8_t>('3'),
      static_cast<uint8_t>('t'),
  };

  const auto formatted = format_ttlv(malformed);
  assert(
      formatted.find("Unable to format KMIP TTLV safely") != std::string::npos
  );
  assert(formatted.find("Raw bytes") == std::string::npos);
  assert(formatted.find("s3cr3t") == std::string::npos);

  std::cout << "KMIP formatter parse-failure redaction test passed"
            << std::endl;
}

void test_logger_interface() {
  CollectingLogger logger;
  assert(logger.shouldLog(LogLevel::Debug));
  assert(!logger.shouldLog(LogLevel::Info));

  logger.log(
      LogRecord{
          .level = LogLevel::Debug,
          .component = "kmip.protocol",
          .event = "request",
          .message = "formatted ttlv"
      }
  );

  assert(logger.records.size() == 1);
  assert(logger.records[0].level == LogLevel::Debug);
  assert(logger.records[0].component == "kmip.protocol");
  assert(logger.records[0].event == "request");
  assert(logger.records[0].message == "formatted ttlv");
  assert(std::string(to_string(LogLevel::Debug)) == "DEBUG");

  std::cout << "Logger interface test passed" << std::endl;
}

int main() {
  test_response_parser_create();
  test_response_parser_locate();
  test_response_parser_discover_versions();
  test_response_parser_discover_versions_empty_payload();
  test_response_parser_query();
  test_response_parser_query_empty_payload();
  test_response_parser_failure_preserves_reason_code();
  test_response_parser_operation_hint_when_operation_absent();
  test_key_parser_symmetric();
  test_key_parser_secret_binary();
  test_key_parser_rejects_out_of_range_secret_type();
  test_key_parser_accepts_extension_secret_type();
  test_register_secret_request_structure();
  test_register_key_request_algorithm_and_length();
  test_get_request_key_format_type();
  test_key_parser_key_format_type();
  test_register_key_request_key_format();
  test_attributes_parser();
  test_attributes_parser_extended();
  test_attributes_parser_v2_typed();
  test_attributes_parser_rejects_out_of_range_enums();
  test_attributes_parser_accepts_extension_values();
  test_attributes_parser_legacy_wrapper_preserves_generic_types();
  test_get_attributes_request_encodes_per_protocol_version();
  test_get_attribute_list_response_supports_v2_attribute_reference();
  test_formatter_for_request_and_response();
  test_formatter_redacts_sensitive_fields();
  test_formatter_parse_failure_omits_raw_bytes();
  test_logger_interface();
  return 0;
}
