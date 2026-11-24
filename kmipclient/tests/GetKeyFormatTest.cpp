/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// Deterministic tests for the Key Format Type op_get_key returns asymmetric
// keys in, against simulated servers with different default and supported
// formats and failure answers, so these paths are covered whichever real
// KMIP server CI uses.

#include "TestKeys.hpp"
#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClient.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/kmip_protocol.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace {

  using kmipclient::KmipClient;
  using kmipcore::Element;
  using kmipcore::tag;

  constexpr int32_t kRaw = kmipcore::KMIP_KEYFORMAT_RAW;
  constexpr int32_t kPkcs1 = kmipcore::KMIP_KEYFORMAT_PKCS1;
  constexpr int32_t kPkcs8 = kmipcore::KMIP_KEYFORMAT_PKCS8;
  constexpr int32_t kX509 = kmipcore::KMIP_KEYFORMAT_X509;
  constexpr int32_t kTransparentEcPrivate =
      kmipcore::KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY;

  struct ServerBehavior {
    int32_t object_type = kmipcore::KMIP_OBJTYPE_PRIVATE_KEY;
    // Format of a Get that asks for none.
    int32_t default_format = kPkcs1;
    // Formats a Get may ask for; any other fails with `unsupported_reason`.
    std::set<int32_t> supported;
    int32_t unsupported_reason =
        kmipcore::KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED;
    // Answer every Get in `default_format`, whatever it asked for.
    bool ignore_requested_format = false;
    // Fail every Get Attributes with this reason; 0 to succeed.
    int32_t get_attributes_failure = 0;
    // Key Material returned in PKCS#8 instead of material_in(kPkcs8), e.g.
    // a real SubjectPublicKeyInfo, as Cosmian KMS labels it.
    std::vector<uint8_t> pkcs8_material;
  };

  // Key material that tells which format it was returned in.
  std::vector<uint8_t> material_in(int32_t format) {
    return std::vector<uint8_t>(16, static_cast<uint8_t>(format));
  }

  bool is_transparent(int32_t format) {
    return format >= kmipcore::KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY &&
           format <= kmipcore::KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY;
  }

  kmipcore::Tag object_tag(int32_t object_type) {
    switch (object_type) {
      case kmipcore::KMIP_OBJTYPE_SYMMETRIC_KEY:
        return tag::KMIP_TAG_SYMMETRIC_KEY;
      case kmipcore::KMIP_OBJTYPE_PUBLIC_KEY:
        return tag::KMIP_TAG_PUBLIC_KEY;
      default:
        return tag::KMIP_TAG_PRIVATE_KEY;
    }
  }

  class FakeGetServer final : public kmipclient::NetClient {
  public:
    explicit FakeGetServer(ServerBehavior behavior)
      : NetClient("host", "5696", "client.pem", "client.key", "ca.pem", 1000),
        behavior_(std::move(behavior)) {
      m_isConnected = true;
    }

    bool connect() override {
      m_isConnected = true;
      return true;
    }

    void close() override { m_isConnected = false; }

    int send(std::span<const std::uint8_t> data) override {
      pending_request_.insert(pending_request_.end(), data.begin(), data.end());
      constexpr std::size_t header = 8;
      if (pending_request_.size() >= header) {
        const std::size_t body = (std::size_t{pending_request_[4]} << 24) |
                                 (std::size_t{pending_request_[5]} << 16) |
                                 (std::size_t{pending_request_[6]} << 8) |
                                 std::size_t{pending_request_[7]};
        if (pending_request_.size() >= header + body) {
          respond();
          pending_request_.clear();
        }
      }
      return static_cast<int>(data.size());
    }

    int recv(std::span<std::uint8_t> data) override {
      const std::size_t count =
          std::min(data.size(), response_.size() - response_offset_);
      std::copy_n(response_.data() + response_offset_, count, data.data());
      response_offset_ += count;
      return static_cast<int>(count);
    }

    // The Key Format Type of every Get received, nullopt for none.
    std::vector<std::optional<int32_t>> get_formats;
    // Request messages received.
    int exchanges = 0;

  private:
    void respond() {
      ++exchanges;
      std::size_t offset = 0;
      const auto request = kmipcore::RequestMessage::fromElement(
          Element::deserialize(pending_request_, offset)
      );

      kmipcore::ResponseMessage response;
      for (const auto &item : request.getBatchItems()) {
        response.add_batch_item(respond_to(item));
      }
      kmipcore::ResponseHeader header;
      header.setProtocolVersion(request.getHeader().getProtocolVersion());
      header.setTimeStamp(0);
      header.setBatchCount(
          static_cast<int32_t>(request.getBatchItems().size())
      );
      response.setHeader(header);

      kmipcore::SerializationBuffer buf;
      response.toElement()->serialize(buf);
      const auto bytes = buf.release();
      response_.assign(bytes.begin(), bytes.end());
      response_offset_ = 0;
    }

    kmipcore::ResponseBatchItem
        respond_to(const kmipcore::RequestBatchItem &item) {
      kmipcore::ResponseBatchItem out;
      out.setUniqueBatchItemId(item.getUniqueBatchItemId());
      out.setOperation(item.getOperation());
      out.setResultStatus(kmipcore::KMIP_STATUS_SUCCESS);
      if (item.getOperation() == kmipcore::KMIP_OP_GET_ATTRIBUTES) {
        if (behavior_.get_attributes_failure != 0) {
          out.setResultStatus(kmipcore::KMIP_STATUS_OPERATION_FAILED);
          out.setResultReason(behavior_.get_attributes_failure);
          out.setResultMessage("Get Attributes failed");
          return out;
        }
        out.setResponsePayload(attributes_payload());
        return out;
      }

      const auto requested =
          item.getRequestPayload()->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE);
      std::optional<int32_t> format;
      if (requested) {
        format = requested->toEnum();
      }
      get_formats.push_back(format);
      if (format && !behavior_.supported.contains(*format)) {
        out.setResultStatus(kmipcore::KMIP_STATUS_OPERATION_FAILED);
        out.setResultReason(behavior_.unsupported_reason);
        out.setResultMessage("unsupported Key Format Type");
        return out;
      }
      if (!format || behavior_.ignore_requested_format) {
        format = behavior_.default_format;
      }
      out.setResponsePayload(get_payload(*format));
      return out;
    }

    std::shared_ptr<Element> get_payload(int32_t format) const {
      auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
      if (is_transparent(format)) {
        // Transparent formats carry a structure of key components, not
        // bytes; its content does not matter here.
        auto material = Element::createStructure(tag::KMIP_TAG_KEY_MATERIAL);
        material->asStructure()->add(
            Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, 256)
        );
        key_value->asStructure()->add(material);
      } else {
        key_value->asStructure()->add(
            Element::createByteString(
                tag::KMIP_TAG_KEY_MATERIAL,
                format == kPkcs8 && !behavior_.pkcs8_material.empty()
                    ? behavior_.pkcs8_material
                    : material_in(format)
            )
        );
      }
      auto key_block = Element::createStructure(tag::KMIP_TAG_KEY_BLOCK);
      key_block->asStructure()->add(
          Element::createEnumeration(tag::KMIP_TAG_KEY_FORMAT_TYPE, format)
      );
      key_block->asStructure()->add(key_value);
      if (behavior_.object_type == kmipcore::KMIP_OBJTYPE_SYMMETRIC_KEY) {
        // A symmetric Key Block states algorithm and length (KMIP 1.4
        // Table 7); material_in() is 16 bytes.
        key_block->asStructure()->add(
            Element::createEnumeration(
                tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
                kmipcore::KMIP_CRYPTOALG_AES
            )
        );
        key_block->asStructure()->add(
            Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, 128)
        );
      }
      auto object = Element::createStructure(object_tag(behavior_.object_type));
      object->asStructure()->add(key_block);

      auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
      payload->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_OBJECT_TYPE, behavior_.object_type
          )
      );
      payload->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "id")
      );
      payload->asStructure()->add(object);
      return payload;
    }

    static std::shared_ptr<Element> attributes_payload() {
      auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
      attribute->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "State")
      );
      attribute->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_ATTRIBUTE_VALUE, kmipcore::KMIP_STATE_ACTIVE
          )
      );
      auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
      payload->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "id")
      );
      payload->asStructure()->add(attribute);
      return payload;
    }

    ServerBehavior behavior_;
    std::vector<std::uint8_t> pending_request_;
    std::vector<std::uint8_t> response_;
    std::size_t response_offset_ = 0;
  };

  struct Fetched {
    std::vector<unsigned char> value;
    std::optional<int32_t> key_format;
  };

  Fetched get_key(
      FakeGetServer &server,
      kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4
  ) {
    KmipClient client(server, {}, version);
    const auto key = client.op_get_key("id");
    return {{key->value().begin(), key->value().end()}, key->key_format()};
  }

  // The key as the server returns it in `format`, labelled `label`.
  void expect_key(
      const Fetched &key, int32_t format, std::optional<int32_t> label
  ) {
    const auto bytes = material_in(format);
    EXPECT_EQ(
        key.value, std::vector<unsigned char>(bytes.begin(), bytes.end())
    );
    EXPECT_EQ(key.key_format, label);
  }

  void expect_get_key_throws(
      FakeGetServer &server,
      int code,
      kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4
  ) {
    try {
      (void) get_key(server, version);
      ADD_FAILURE() << "expected a KmipException, got a key";
    } catch (const kmipcore::KmipException &e) {
      EXPECT_EQ(e.code().value(), code) << e.what();
    }
  }

  using Formats = std::vector<std::optional<int32_t>>;

  // A real P-256 SubjectPublicKeyInfo, as a server would hold.
  std::vector<uint8_t> subject_public_key_info() {
    const auto pair = kmipclient_test::generate_key_pair(EVP_PKEY_EC);
    return {pair.public_key.value().begin(), pair.public_key.value().end()};
  }

}  // namespace

TEST(GetKeyFormatTest, SymmetricKeyIsFetchedOnceWithoutAskingForAFormat) {
  FakeGetServer server(
      {.object_type = kmipcore::KMIP_OBJTYPE_SYMMETRIC_KEY,
       .default_format = kRaw}
  );
  expect_key(get_key(server), kRaw, kRaw);
  EXPECT_EQ(server.get_formats, Formats{std::nullopt});
}

TEST(GetKeyFormatTest, PrivateKeyAlreadyInPkcs8IsFetchedOnce) {
  FakeGetServer server({.default_format = kPkcs8});
  expect_key(get_key(server), kPkcs8, kPkcs8);
  EXPECT_EQ(server.get_formats, Formats{std::nullopt});
}

TEST(GetKeyFormatTest, PrivateKeyInPkcs1IsFetchedAgainAsPkcs8) {
  FakeGetServer server({.default_format = kPkcs1, .supported = {kPkcs8}});
  expect_key(get_key(server), kPkcs8, kPkcs8);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kPkcs8}));
}

// Cosmian KMS returns EC keys as a Transparent structure, which has no byte
// encoding: parsing it used to throw.
TEST(GetKeyFormatTest, TransparentEcPrivateKeyIsFetchedAgainAsPkcs8) {
  FakeGetServer server(
      {.default_format = kTransparentEcPrivate, .supported = {kPkcs8}}
  );
  expect_key(get_key(server), kPkcs8, kPkcs8);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kPkcs8}));
}

// Converting is optional for a server (KMIP 1.4 §4.11): without it, the key
// comes back in the server's format, labelled as such, so registering it
// again declares PKCS#1 rather than mislabelling the bytes as PKCS#8.
TEST(GetKeyFormatTest, KeepsTheServerFormatWhenItCannotConvert) {
  FakeGetServer server({.default_format = kPkcs1, .supported = {}});
  expect_key(get_key(server), kPkcs1, kPkcs1);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kPkcs8}));
}

TEST(GetKeyFormatTest, KeepsTheServerFormatWhenItIgnoresTheRequest) {
  FakeGetServer server(
      {.default_format = kPkcs1,
       .supported = {kPkcs8},
       .ignore_requested_format = true}
  );
  expect_key(get_key(server), kPkcs1, kPkcs1);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kPkcs8}));
}

// A Transparent format has no bytes to fall back to.
TEST(GetKeyFormatTest, ThrowsForTransparentKeyTheServerCannotConvert) {
  FakeGetServer server({.default_format = kTransparentEcPrivate});
  expect_get_key_throws(server, kmipcore::KMIP_NOT_IMPLEMENTED);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kPkcs8}));
}

TEST(GetKeyFormatTest, PublicKeyIsFetchedAgainAsX509) {
  FakeGetServer server(
      {.object_type = kmipcore::KMIP_OBJTYPE_PUBLIC_KEY,
       .default_format = kPkcs1,
       .supported = {kX509, kPkcs8}}
  );
  expect_key(get_key(server), kX509, kX509);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kX509}));
}

// Cosmian KMS deviates from KMIP: it exports a public key's
// SubjectPublicKeyInfo only under the PKCS#8 label, and refuses X.509 with
// Operation Not Supported. The key is recorded as X.509, its KMIP name.
TEST(GetKeyFormatTest, PublicKeyFallsBackToCosmianPkcs8Label) {
  const auto spki = subject_public_key_info();
  FakeGetServer server(
      {.object_type = kmipcore::KMIP_OBJTYPE_PUBLIC_KEY,
       .default_format = kPkcs1,
       .supported = {kPkcs8},
       .unsupported_reason = kmipcore::KMIP_REASON_OPERATION_NOT_SUPPORTED,
       .pkcs8_material = spki}
  );
  const auto key = get_key(server);
  EXPECT_EQ(key.value, std::vector<unsigned char>(spki.begin(), spki.end()));
  EXPECT_EQ(key.key_format, kX509);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kX509, kPkcs8}));
}

TEST(GetKeyFormatTest, PublicKeyUnderCosmianPkcs8LabelIsFetchedOnce) {
  const auto spki = subject_public_key_info();
  FakeGetServer server(
      {.object_type = kmipcore::KMIP_OBJTYPE_PUBLIC_KEY,
       .default_format = kPkcs8,
       .pkcs8_material = spki}
  );
  const auto key = get_key(server);
  EXPECT_EQ(key.value, std::vector<unsigned char>(spki.begin(), spki.end()));
  EXPECT_EQ(key.key_format, kX509);
  EXPECT_EQ(server.get_formats, Formats{std::nullopt});
}

// Checking for a SubjectPublicKeyInfo parses the key, and on OpenSSL 1.1.1
// that parse sets and pops a mark of its own: the caller's pending OpenSSL
// errors must survive it.
TEST(GetKeyFormatTest, SpkiCheckKeepsTheCallersOpenSSLErrors) {
  FakeGetServer server(
      {.object_type = kmipcore::KMIP_OBJTYPE_PUBLIC_KEY,
       .default_format = kPkcs8,
       .pkcs8_material = subject_public_key_info()}
  );
  ERR_clear_error();
  const unsigned char junk[] = {0x00};
  const unsigned char *p = junk;
  (void) d2i_X509(nullptr, &p, sizeof(junk));
  const unsigned long callers = ERR_peek_last_error();
  ASSERT_NE(callers, 0u);
  EXPECT_EQ(get_key(server).key_format, kX509);
  EXPECT_EQ(ERR_peek_last_error(), callers);
  ERR_clear_error();
}

// Only a SubjectPublicKeyInfo is X.509: other bytes under the PKCS#8 label
// are no public key format KMIP defines, so X.509 is asked for. If the
// server cannot convert, the key keeps the server's label rather than be
// registered as X.509 later.
TEST(GetKeyFormatTest, PublicKeyUnderPkcs8LabelThatIsNotSpkiKeepsTheLabel) {
  FakeGetServer server(
      {.object_type = kmipcore::KMIP_OBJTYPE_PUBLIC_KEY,
       .default_format = kPkcs8}
  );
  expect_key(get_key(server), kPkcs8, kPkcs8);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kX509, kPkcs8}));
}

TEST(GetKeyFormatTest, PublicKeyUnderPkcs8LabelThatIsNotSpkiIsFetchedAsX509) {
  FakeGetServer server(
      {.object_type = kmipcore::KMIP_OBJTYPE_PUBLIC_KEY,
       .default_format = kPkcs8,
       .supported = {kX509}}
  );
  expect_key(get_key(server), kX509, kX509);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kX509}));
}

// A PKCS#8 answer with no SubjectPublicKeyInfo counts as a refusal: the
// server's own PKCS#1 key is kept, not replaced by it.
TEST(GetKeyFormatTest, PublicKeyKeepsPkcs1OverPkcs8LabelThatIsNotSpki) {
  FakeGetServer server(
      {.object_type = kmipcore::KMIP_OBJTYPE_PUBLIC_KEY,
       .default_format = kPkcs1,
       .supported = {kPkcs8}}
  );
  expect_key(get_key(server), kPkcs1, kPkcs1);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kX509, kPkcs8}));
}

TEST(GetKeyFormatTest, PublicKeyKeepsTheServerFormatWhenItCannotConvert) {
  FakeGetServer server(
      {.object_type = kmipcore::KMIP_OBJTYPE_PUBLIC_KEY,
       .default_format = kPkcs1,
       .supported = {}}
  );
  expect_key(get_key(server), kPkcs1, kPkcs1);
  EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kX509, kPkcs8}));
}

// The plain Get just worked, so any refusal of a format, with whatever
// reason, keeps the key as first returned: a server that answers Invalid
// Field gets the same result as master gave, on both protocol versions,
// and the Get Attributes retries for KMIP 2.0 do not kick in.
TEST(GetKeyFormatTest, AnyRefusalKeepsTheServerFormat) {
  for (const auto version :
       {kmipcore::KMIP_VERSION_1_4, kmipcore::KMIP_VERSION_2_0}) {
    for (const int32_t reason :
         {kmipcore::KMIP_REASON_INVALID_FIELD,
          kmipcore::KMIP_REASON_PERMISSION_DENIED}) {
      FakeGetServer server(
          {.default_format = kPkcs1,
           .supported = {},
           .unsupported_reason = reason}
      );
      expect_key(get_key(server, version), kPkcs1, kPkcs1);
      EXPECT_EQ(server.get_formats, (Formats{std::nullopt, kPkcs8}));
      EXPECT_EQ(server.exchanges, 2);
    }
  }
}

// Get Attributes is checked before asking for the key again, so its KMIP
// 2.0 retries cost what they did before: no extra Get per attempt.
TEST(GetKeyFormatTest, NoRefetchWhenGetAttributesFails) {
  FakeGetServer server(
      {.default_format = kPkcs1,
       .supported = {kPkcs8},
       .get_attributes_failure = kmipcore::KMIP_REASON_INVALID_FIELD}
  );
  expect_get_key_throws(
      server, kmipcore::KMIP_REASON_INVALID_FIELD, kmipcore::KMIP_VERSION_2_0
  );
  // Selected attributes, legacy names, then all attributes: three batches.
  EXPECT_EQ(
      server.get_formats, (Formats{std::nullopt, std::nullopt, std::nullopt})
  );
  EXPECT_EQ(server.exchanges, 3);
}
