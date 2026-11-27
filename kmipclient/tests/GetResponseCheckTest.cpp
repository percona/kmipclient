/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// Get and Get Attributes responses must be about the requested object, and a
// symmetric key's material must match its stated Cryptographic Length.

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
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {

  using kmipclient::KmipClient;
  using kmipcore::Element;
  using kmipcore::KeyType;
  using kmipcore::tag;

  constexpr const char *kRequestedId = "key-A";
  // As an identifier: send an Integer instead of a Text String.
  constexpr const char *kIntegerId = "<integer>";

  struct Behavior {
    int32_t object_type = kmipcore::KMIP_OBJTYPE_SYMMETRIC_KEY;
    int32_t key_format = kmipcore::KMIP_KEYFORMAT_RAW;
    std::optional<int32_t> algorithm = kmipcore::KMIP_CRYPTOALG_AES;
    std::optional<int32_t> length = 256;  // in the Key Block
    std::optional<int32_t> attributes_algorithm;
    std::optional<int32_t> attributes_length;
    // Algorithm and length go into the Key Value's KMIP 2.0 Attributes
    // structure instead of the Key Block.
    bool lengths_in_key_value = false;
    std::vector<uint8_t> material = std::vector<uint8_t>(32, 0x5A);
    std::string get_id = kRequestedId;
    // Gets after the first.
    std::optional<std::string> later_get_id;
    std::optional<int32_t> later_object_type;
    std::optional<int32_t> later_key_format;
    std::optional<std::string> attributes_id = std::string(kRequestedId);
  };

  Behavior secret_data() {
    Behavior b;
    b.object_type = kmipcore::KMIP_OBJTYPE_SECRET_DATA;
    b.key_format = kmipcore::KMIP_KEYFORMAT_OPAQUE;
    b.algorithm.reset();
    b.length.reset();
    return b;
  }

  using E = Element;
  using ElementPtr = std::shared_ptr<Element>;

  void add(const ElementPtr &parent, ElementPtr child) {
    parent->asStructure()->add(std::move(child));
  }

  ElementPtr unique_id(const std::string &id) {
    return id == kIntegerId
             ? E::createInteger(tag::KMIP_TAG_UNIQUE_IDENTIFIER, 1)
             : E::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, id);
  }

  ElementPtr attribute(const char *name, ElementPtr value) {
    auto a = E::createStructure(tag::KMIP_TAG_ATTRIBUTE);
    add(a, E::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, name));
    add(a, std::move(value));
    return a;
  }

  // Answers each Get and Get Attributes batch item from a Behavior. IOUtils
  // hands over a whole request in one send().
  class FakeObjectServer final : public kmipclient::NetClient {
  public:
    explicit FakeObjectServer(Behavior behavior)
      : NetClient("host", "5696", "client.pem", "client.key", "ca.pem", 1000),
        b_(std::move(behavior)) {
      m_isConnected = true;
    }

    bool connect() override { return m_isConnected = true; }
    void close() override { m_isConnected = false; }

    int send(std::span<const std::uint8_t> data) override {
      ++exchanges;
      std::size_t pos = 0;
      const auto request =
          kmipcore::RequestMessage::fromElement(E::deserialize(data, pos));
      kmipcore::ResponseMessage response;
      for (const auto &item : request.getBatchItems()) {
        kmipcore::ResponseBatchItem out;
        out.setUniqueBatchItemId(item.getUniqueBatchItemId());
        out.setOperation(item.getOperation());
        out.setResultStatus(kmipcore::KMIP_STATUS_SUCCESS);
        out.setResponsePayload(
            item.getOperation() == kmipcore::KMIP_OP_GET_ATTRIBUTES
                ? attributes_payload()
                : get_payload()
        );
        response.add_batch_item(out);
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
      offset_ = 0;
      return static_cast<int>(data.size());
    }

    int recv(std::span<std::uint8_t> data) override {
      const std::size_t n = std::min(data.size(), response_.size() - offset_);
      std::copy_n(response_.data() + offset_, n, data.data());
      offset_ += n;
      return static_cast<int>(n);
    }

    int exchanges = 0;  // request messages received

  private:
    ElementPtr get_payload() {
      const bool first = gets_++ == 0;
      const int32_t object_type =
          first ? b_.object_type
                : b_.later_object_type.value_or(b_.object_type);
      const int32_t key_format =
          first ? b_.key_format : b_.later_key_format.value_or(b_.key_format);

      auto value = E::createStructure(tag::KMIP_TAG_KEY_VALUE);
      add(value, E::createByteString(tag::KMIP_TAG_KEY_MATERIAL, b_.material));
      auto block = E::createStructure(tag::KMIP_TAG_KEY_BLOCK);
      add(block,
          E::createEnumeration(tag::KMIP_TAG_KEY_FORMAT_TYPE, key_format));
      add(block, value);
      const auto lengths = b_.lengths_in_key_value
                             ? E::createStructure(tag::KMIP_TAG_ATTRIBUTES)
                             : block;
      if (b_.lengths_in_key_value) {
        add(value, lengths);
      }
      if (b_.algorithm) {
        add(lengths,
            E::createEnumeration(
                tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, *b_.algorithm
            ));
      }
      if (b_.length) {
        add(lengths,
            E::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, *b_.length));
      }

      ElementPtr object;
      if (object_type == kmipcore::KMIP_OBJTYPE_SECRET_DATA) {
        object = E::createStructure(tag::KMIP_TAG_SECRET_DATA);
        add(object,
            E::createEnumeration(
                tag::KMIP_TAG_SECRET_DATA_TYPE, kmipcore::KMIP_SECDATA_PASSWORD
            ));
      } else if (object_type == kmipcore::KMIP_OBJTYPE_PRIVATE_KEY) {
        object = E::createStructure(tag::KMIP_TAG_PRIVATE_KEY);
      } else if (object_type == kmipcore::KMIP_OBJTYPE_PUBLIC_KEY) {
        object = E::createStructure(tag::KMIP_TAG_PUBLIC_KEY);
      } else {
        object = E::createStructure(tag::KMIP_TAG_SYMMETRIC_KEY);
      }
      add(object, block);

      auto payload = E::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
      add(payload,
          E::createEnumeration(tag::KMIP_TAG_OBJECT_TYPE, object_type));
      add(payload,
          unique_id(first || !b_.later_get_id ? b_.get_id : *b_.later_get_id));
      add(payload, object);
      return payload;
    }

    ElementPtr attributes_payload() const {
      auto payload = E::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
      if (b_.attributes_id) {
        add(payload, unique_id(*b_.attributes_id));
      }
      add(payload,
          attribute(
              "State",
              E::createEnumeration(
                  tag::KMIP_TAG_ATTRIBUTE_VALUE, kmipcore::KMIP_STATE_ACTIVE
              )
          ));
      if (b_.attributes_algorithm) {
        add(payload,
            attribute(
                "Cryptographic Algorithm",
                E::createEnumeration(
                    tag::KMIP_TAG_ATTRIBUTE_VALUE, *b_.attributes_algorithm
                )
            ));
      }
      if (b_.attributes_length) {
        add(payload,
            attribute(
                "Cryptographic Length",
                E::createInteger(
                    tag::KMIP_TAG_ATTRIBUTE_VALUE, *b_.attributes_length
                )
            ));
      }
      return payload;
    }

    Behavior b_;
    int gets_ = 0;
    std::vector<std::uint8_t> response_;
    std::size_t offset_ = 0;
  };

  enum class Op { get_key, get_key_all_attributes, get_secret, get_attributes };

  struct Outcome {
    std::string error;  // "" when the operation succeeded
    int code = 0;
    int exchanges = 0;
    std::optional<KeyType> key_type;  // op_get_key's result
    std::optional<int32_t> key_format;
  };

  Outcome
      run(Op op,
          const Behavior &b,
          kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4) {
    FakeObjectServer server(b);
    KmipClient client(server, {}, version);
    Outcome out;
    try {
      switch (op) {
        case Op::get_key:
        case Op::get_key_all_attributes: {
          const auto key =
              client.op_get_key(kRequestedId, op == Op::get_key_all_attributes);
          EXPECT_EQ(key->value().size(), b.material.size());
          out.key_type = key->type();
          out.key_format = key->key_format();
          break;
        }
        case Op::get_secret:
          (void) client.op_get_secret(kRequestedId);
          break;
        case Op::get_attributes:
          (void) client.op_get_attributes(kRequestedId, {"State"});
          break;
      }
    } catch (const kmipcore::KmipException &e) {
      out.error = e.what();
      out.code = e.code().value();
    }
    out.exchanges = server.exchanges;
    return out;
  }

}  // namespace

TEST(GetResponseCheckTest, ResponseForAnotherObjectIsRejected) {
  struct Case {
    Op op;
    bool wrong_get;  // else the Get Attributes response is the wrong one
  };
  const std::vector<Case> cases{
      {Op::get_key, true},
      {Op::get_key, false},
      {Op::get_key_all_attributes, true},
      {Op::get_key_all_attributes, false},
      {Op::get_secret, true},
      {Op::get_secret, false},
      {Op::get_attributes, false},
  };
  // Over KMIP 2.0 too: a mismatch must not trigger the Get Attributes retry.
  for (const auto version :
       {kmipcore::KMIP_VERSION_1_4, kmipcore::KMIP_VERSION_2_0}) {
    for (std::size_t i = 0; i < cases.size(); ++i) {
      Behavior b = cases[i].op == Op::get_secret ? secret_data() : Behavior{};
      if (cases[i].wrong_get) {
        b.get_id = "key-B";
      } else {
        b.attributes_id = "key-B";
      }
      const auto out = run(cases[i].op, b, version);
      EXPECT_EQ(out.code, kmipcore::KMIP_OBJECT_MISMATCH)
          << "case " << i << ": " << out.error;
      EXPECT_EQ(out.exchanges, 1) << "case " << i;
    }
  }
}

TEST(GetResponseCheckTest, PreferredFormatRefetchIsChecked) {
  // A PKCS#1 private key makes op_get_key ask again for PKCS#8; the second
  // Get answers for another object.
  Behavior b;
  b.object_type = kmipcore::KMIP_OBJTYPE_PRIVATE_KEY;
  b.key_format = kmipcore::KMIP_KEYFORMAT_PKCS1;
  b.algorithm = kmipcore::KMIP_CRYPTOALG_RSA;
  b.length = 2048;
  b.later_get_id = "key-B";
  const auto out = run(Op::get_key, b);
  EXPECT_EQ(out.code, kmipcore::KMIP_OBJECT_MISMATCH) << out.error;
  EXPECT_EQ(out.exchanges, 2);
}

TEST(GetResponseCheckTest, PreferredFormatRefetchOfAnotherTypeIsSkipped) {
  // A PKCS#1 public key makes op_get_key ask again for X.509, then PKCS#8.
  // Both answers are a private key under the same identifier, in the
  // requested format; op_get_key keeps the public key it got first.
  Behavior b;
  b.object_type = kmipcore::KMIP_OBJTYPE_PUBLIC_KEY;
  b.key_format = kmipcore::KMIP_KEYFORMAT_PKCS1;
  b.algorithm = kmipcore::KMIP_CRYPTOALG_RSA;
  b.length = 2048;
  b.later_object_type = kmipcore::KMIP_OBJTYPE_PRIVATE_KEY;
  b.later_key_format = kmipcore::KMIP_KEYFORMAT_X509;
  const auto out = run(Op::get_key, b);
  EXPECT_EQ(out.error, "");
  EXPECT_EQ(out.key_type, KeyType::PUBLIC_KEY);
  EXPECT_EQ(out.key_format, kmipcore::KMIP_KEYFORMAT_PKCS1);
  EXPECT_EQ(out.exchanges, 3);

  // Control: the same answers for a public key are taken.
  b.later_object_type.reset();
  const auto control = run(Op::get_key, b);
  EXPECT_EQ(control.error, "");
  EXPECT_EQ(control.key_type, KeyType::PUBLIC_KEY);
  EXPECT_EQ(control.key_format, kmipcore::KMIP_KEYFORMAT_X509);
}

TEST(GetResponseCheckTest, IdentifierForms) {
  struct Case {
    std::string get_id;
    std::optional<std::string> attributes_id;
    std::string expected;  // part of the error; "" when accepted
  };
  const std::vector<Case> cases{
      {kIntegerId, kRequestedId, "not a Text String"},
      {kRequestedId, kIntegerId, "not a Text String"},
      {kRequestedId, std::nullopt, ""},  // Get Attributes may omit it
      // A long identifier is shortened in the message.
      {std::string(1000, 'x'), kRequestedId, std::string(64, 'x') + "...'"},
      // Bytes outside printable ASCII are shown as '?'.
      {"key\nB\x01\x7f\xc3\xa9",
       kRequestedId,
       "'key?B" + std::string(4, '?') + "'"},
  };
  for (const auto &c : cases) {
    Behavior b;
    b.get_id = c.get_id;
    b.attributes_id = c.attributes_id;
    const auto error = run(Op::get_key, b).error;
    if (c.expected.empty()) {
      EXPECT_EQ(error, "");
    } else {
      EXPECT_NE(error.find(c.expected), std::string::npos) << error;
      EXPECT_EQ(error.find(std::string(65, 'x')), std::string::npos);
      EXPECT_EQ(error.find('\n'), std::string::npos);
    }
  }
}

TEST(GetResponseCheckTest, SymmetricKeyMaterialMatchesItsLength) {
  constexpr int32_t AES = kmipcore::KMIP_CRYPTOALG_AES;
  constexpr int32_t DES = kmipcore::KMIP_CRYPTOALG_DES;
  constexpr int32_t TDES = kmipcore::KMIP_CRYPTOALG_TRIPLE_DES;
  constexpr std::nullopt_t none = std::nullopt;
  struct Case {
    int32_t algorithm;
    std::optional<int32_t> block_length;
    std::optional<int32_t> attributes_length;
    std::size_t bytes;
    std::string expected;  // part of the error; "" when accepted
    std::optional<int32_t> attributes_algorithm = std::nullopt;
  };
  const std::vector<Case> cases{
      {AES, 256, none, 32, ""},
      {AES, 256, none, 0, "is empty"},
      {AES, 256, none, 16, "Cryptographic Length is 256"},
      {AES, 128, none, 32, "has 256 bits"},
      // DES and 3DES: with or without the parity bits (KMIP 1.4 §2.1.3).
      {DES, 56, none, 7, ""},
      {DES, 56, none, 8, ""},
      {TDES, 168, none, 21, ""},
      {TDES, 168, none, 24, ""},
      {TDES, 192, none, 24, ""},
      {TDES, 168, none, 20, "Cryptographic Length is 168"},
      // The parity rule is for DES and 3DES only, and for lengths that
      // count 7 bits per byte; a length that counts the parity bits must
      // come with material that has them.
      {AES, 168, none, 24, "Cryptographic Length is 168"},
      {TDES, 170, none, 24, "Cryptographic Length is 170"},
      {TDES, 192, none, 21, "Cryptographic Length is 192"},
      {DES, 64, none, 7, "Cryptographic Length is 64"},
      {TDES, 192, 168, 24, ""},
      {TDES, INT32_MAX, none, 24, "Cryptographic Length is"},
      {TDES, -8, none, 24, "Cryptographic Length is"},
      // The length in Get Attributes is checked too, and is enough alone.
      {AES, none, 256, 32, ""},
      {AES, none, 256, 1, "Cryptographic Length is 256"},
      {AES, 128, 256, 16, "Cryptographic Length is 256"},
      {AES, 256, 128, 16, "Cryptographic Length is 256"},
      // The Key Block and the attributes must name the same algorithm.
      {AES, 256, 224, 32, "Cryptographic Algorithm is", DES},
      {AES, 256, none, 32, "", AES},
      {AES, none, none, 16, "has no Cryptographic Length"},
  };
  for (std::size_t i = 0; i < cases.size(); ++i) {
    const Case &c = cases[i];
    Behavior b;
    b.algorithm = c.algorithm;
    b.length = c.block_length;
    b.attributes_length = c.attributes_length;
    b.attributes_algorithm = c.attributes_algorithm;
    b.material.assign(c.bytes, 0x33);
    const auto error = run(Op::get_key, b).error;
    if (c.expected.empty()) {
      EXPECT_EQ(error, "") << "case " << i;
    } else {
      EXPECT_NE(error.find(c.expected), std::string::npos)
          << "case " << i << ": " << error;
    }
  }
}

// KMIP 2.0 puts attributes encapsulated with the key material in an
// Attributes structure in the Key Value (2.0 §3.2); the Key Block may then
// leave algorithm and length out.
TEST(GetResponseCheckTest, KeyValueAttributesAreRead) {
  for (const auto [length, expected] :
       {std::pair{256, ""}, std::pair{128, "Cryptographic Length is 128"}}) {
    SCOPED_TRACE(length);
    Behavior b;  // 32 bytes of AES; Get Attributes states no length
    b.length = length;
    b.lengths_in_key_value = true;
    const auto out = run(Op::get_key, b, kmipcore::KMIP_VERSION_2_0);
    if (*expected == '\0') {
      EXPECT_EQ(out.error, "");
    } else {
      EXPECT_NE(out.error.find(expected), std::string::npos) << out.error;
    }
  }
}
