/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "../src/IOUtils.hpp"

#include "kmipclient/Kmip.hpp"
#include "kmipclient/KmipIOException.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/kmip_logger.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace {

  class CollectingLogger final : public kmipcore::Logger {
  public:
    [[nodiscard]] bool shouldLog(kmipcore::LogLevel level) const override {
      return level == kmipcore::LogLevel::Debug;
    }

    void log(const kmipcore::LogRecord &record) override {
      records.push_back(record);
    }

    std::vector<kmipcore::LogRecord> records;
  };

  class FakeNetClient final : public kmipclient::NetClient {
  public:
    FakeNetClient()
      : NetClient("host", "5696", "client.pem", "client.key", "ca.pem", 1000) {}

    bool connect() override {
      ++connect_calls;
      m_isConnected = connect_result;
      return connect_result;
    }

    void close() override {
      ++close_calls;
      m_isConnected = false;
    }

    int send(std::span<const std::uint8_t> data) override {
      ++send_calls;

      const int desired = send_plan_index < static_cast<int>(send_plan.size())
                            ? send_plan[send_plan_index++]
                            : static_cast<int>(data.size());
      if (desired <= 0) {
        return desired;
      }

      const int sent = std::min(desired, static_cast<int>(data.size()));
      sent_bytes.insert(sent_bytes.end(), data.begin(), data.begin() + sent);
      return sent;
    }

    int recv(std::span<std::uint8_t> data) override {
      if (recv_offset >= response_bytes.size()) {
        return 0;
      }

      const size_t count =
          std::min(data.size(), response_bytes.size() - recv_offset);
      std::copy_n(response_bytes.data() + recv_offset, count, data.data());
      recv_offset += count;
      return static_cast<int>(count);
    }

    std::vector<int> send_plan;
    std::vector<uint8_t> response_bytes;
    std::vector<uint8_t> sent_bytes;
    int send_calls = 0;
    bool connect_result = true;
    int connect_calls = 0;
    int close_calls = 0;

  private:
    int send_plan_index = 0;
    size_t recv_offset = 0;
  };

  // Returns one byte per recv() after a pause (with whole_reads, all the
  // bytes asked for), takes one byte per send() after a pause when
  // trickle_send is set, and records the deadline it sees on every call.
  class TricklingNetClient final : public kmipclient::NetClient {
  public:
    TricklingNetClient(int timeout_ms, std::chrono::milliseconds per_byte)
      : NetClient("host", "5696", "c.pem", "c.key", "ca.pem", timeout_ms),
        per_byte_(per_byte) {}

    bool connect() override {
      std::this_thread::sleep_for(connect_delay);
      m_isConnected = true;
      return true;
    }
    void close() override { m_isConnected = false; }

    int send(std::span<const std::uint8_t> data) override {
      if (!is_connected()) {
        connect();  // as NetClientOpenSSL does
      }
      deadlines_seen.push_back(io_deadline());
      if (trickle_send && !data.empty()) {
        std::this_thread::sleep_for(per_byte_);
        return 1;
      }
      return static_cast<int>(data.size());
    }

    int recv(std::span<std::uint8_t> data) override {
      deadlines_seen.push_back(io_deadline());
      if (data.empty() || offset_ >= response_bytes.size()) {
        return 0;
      }
      std::this_thread::sleep_for(per_byte_);
      const size_t count =
          whole_reads ? std::min(data.size(), response_bytes.size() - offset_)
                      : 1;
      std::copy_n(response_bytes.data() + offset_, count, data.data());
      offset_ += count;
      return static_cast<int>(count);
    }

    std::vector<uint8_t> response_bytes;
    std::vector<std::optional<Clock::time_point>> deadlines_seen;
    std::chrono::milliseconds connect_delay{0};
    bool trickle_send = false;
    bool whole_reads = false;

  private:
    std::chrono::milliseconds per_byte_;
    size_t offset_ = 0;
  };

  // Forwards every call to a wrapped NetClient and keeps no state of its own.
  class ForwardingNetClient final : public kmipclient::NetClient {
  public:
    explicit ForwardingNetClient(kmipclient::NetClient &inner)
      : NetClient(
            "host", "5696", "c.pem", "c.key", "ca.pem", inner.timeout_ms()
        ),
        inner_(inner) {}

    bool connect() override { return inner_.connect(); }
    void close() override { inner_.close(); }
    [[nodiscard]] bool is_connected() const noexcept override {
      return inner_.is_connected();
    }
    void set_io_deadline(
        std::optional<Clock::time_point> deadline
    ) noexcept override {
      NetClient::set_io_deadline(deadline);
      inner_.set_io_deadline(deadline);
    }
    int send(std::span<const std::uint8_t> data) override {
      return inner_.send(data);
    }
    int recv(std::span<std::uint8_t> data) override {
      return inner_.recv(data);
    }

  private:
    kmipclient::NetClient &inner_;
  };

  // Runs do_exchange() and returns the message of the KmipIOException it
  // throws, or "" when it succeeds.
  std::string exchange_error(
      kmipclient::IOUtils &io,
      std::span<const uint8_t> request,
      size_t max_message_size = 1024
  ) {
    kmipcore::secure_bytes response;
    try {
      io.do_exchange(request, response, max_message_size);
    } catch (const kmipclient::KmipIOException &e) {
      return e.what();
    }
    return "";
  }

  testing::AssertionResult
      contains(const std::string &text, const std::string &part) {
    if (text.find(part) != std::string::npos) {
      return testing::AssertionSuccess();
    }
    return testing::AssertionFailure()
        << "\"" << text << "\" does not contain \"" << part << "\"";
  }

  std::vector<uint8_t>
      build_response_with_payload(const std::vector<uint8_t> &payload) {
    const auto len = static_cast<int32_t>(payload.size());
    std::vector<uint8_t> out{
        0,
        0,
        0,
        0,
        static_cast<uint8_t>((len >> 24) & 0xFF),
        static_cast<uint8_t>((len >> 16) & 0xFF),
        static_cast<uint8_t>((len >> 8) & 0xFF),
        static_cast<uint8_t>(len & 0xFF)
    };
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
  }

  kmipcore::secure_bytes
      serialize_element(const std::shared_ptr<kmipcore::Element> &element) {
    kmipcore::SerializationBuffer buf;
    element->serialize(buf);
    return buf.release();
  }

}  // namespace

static_assert(
    std::is_move_constructible_v<kmipclient::Kmip>,
    "Kmip must be move-constructible"
);
static_assert(
    std::is_move_assignable_v<kmipclient::Kmip>, "Kmip must be move-assignable"
);
static_assert(
    !std::is_copy_constructible_v<kmipclient::Kmip>,
    "Kmip must remain non-copyable"
);
static_assert(
    !std::is_copy_assignable_v<kmipclient::Kmip>,
    "Kmip must remain non-copy-assignable"
);

TEST(IOUtilsTest, SendRetriesOnShortWritesUntilComplete) {
  FakeNetClient nc;
  nc.send_plan = {3, 2, 128};
  nc.response_bytes = build_response_with_payload({0x42});

  kmipclient::IOUtils io(nc);
  const std::vector<uint8_t> request{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  kmipcore::secure_bytes response;

  ASSERT_NO_THROW(io.do_exchange(request, response, 1024));
  EXPECT_EQ(nc.sent_bytes, request);
  EXPECT_EQ(nc.send_calls, 3);
  EXPECT_EQ(response, nc.response_bytes);
}

TEST(IOUtilsTest, SendFailsIfTransportStopsProgress) {
  FakeNetClient nc;
  nc.send_plan = {2, 0};
  nc.response_bytes = build_response_with_payload({0x42});

  kmipclient::IOUtils io(nc);
  const std::vector<uint8_t> request{0, 1, 2, 3};
  kmipcore::secure_bytes response;

  EXPECT_THROW(
      io.do_exchange(request, response, 1024), kmipclient::KmipIOException
  );
}

TEST(IOUtilsTest, AcceptsResponsesLargerThanLegacy64KiBLimit) {
  FakeNetClient nc;
  const std::size_t payload_size = 128 * 1024;
  nc.response_bytes =
      build_response_with_payload(std::vector<uint8_t>(payload_size, 0xAB));

  kmipclient::IOUtils io(nc);
  const std::vector<uint8_t> request{0x01};
  kmipcore::secure_bytes response;

  ASSERT_NO_THROW(
      io.do_exchange(request, response, kmipcore::KMIP_MAX_MESSAGE_SIZE)
  );
  EXPECT_EQ(response, nc.response_bytes);
}

TEST(IOUtilsTest, RejectsResponseThatExceedsCallerLimit) {
  FakeNetClient nc;
  nc.response_bytes =
      build_response_with_payload(std::vector<uint8_t>(2048, 0x11));

  kmipclient::IOUtils io(nc);
  const std::vector<uint8_t> request{0x01};
  kmipcore::secure_bytes response;

  try {
    io.do_exchange(request, response, 1024);
    FAIL() << "Expected do_exchange to reject oversized response";
  } catch (const kmipclient::KmipIOException &e) {
    EXPECT_EQ(e.code().value(), kmipcore::KMIP_EXCEED_MAX_MESSAGE_SIZE);
    EXPECT_NE(std::string(e.what()).find("allowed: 1024"), std::string::npos);
  }
}

TEST(
    IOUtilsTest, RejectsResponseThatExceedsHardLimitEvenIfCallerLimitIsHigher
) {
  FakeNetClient nc;
  nc.response_bytes = build_response_with_payload(
      std::vector<uint8_t>(kmipcore::KMIP_MAX_MESSAGE_HARD_LIMIT + 1, 0x22)
  );

  kmipclient::IOUtils io(nc);
  const std::vector<uint8_t> request{0x01};
  kmipcore::secure_bytes response;

  try {
    io.do_exchange(
        request, response, kmipcore::KMIP_MAX_MESSAGE_HARD_LIMIT * 2
    );
    FAIL() << "Expected do_exchange to enforce hard response limit";
  } catch (const kmipclient::KmipIOException &e) {
    EXPECT_EQ(e.code().value(), kmipcore::KMIP_EXCEED_MAX_MESSAGE_SIZE);
    EXPECT_NE(
        std::string(e.what()).find(
            "allowed: " + std::to_string(kmipcore::KMIP_MAX_MESSAGE_HARD_LIMIT)
        ),
        std::string::npos
    );
  }
}

TEST(IOUtilsTest, TimeoutBoundsTheWholeExchange) {
  // 400 bytes at 5 ms each take 2 s; every single call is far below the
  // 200 ms timeout, so only a deadline for the whole exchange stops it.
  TricklingNetClient nc(200, std::chrono::milliseconds(5));
  nc.response_bytes = build_response_with_payload(std::vector<uint8_t>(392));
  kmipclient::IOUtils io(nc);
  kmipcore::secure_bytes response;

  const auto start = std::chrono::steady_clock::now();
  EXPECT_THROW(
      io.do_exchange(std::vector<uint8_t>{0, 1, 2, 3}, response, 1 << 20),
      kmipclient::KmipIOException
  );
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(1));

  // One deadline, the same on every call, cleared afterwards.
  ASSERT_FALSE(nc.deadlines_seen.empty());
  ASSERT_TRUE(nc.deadlines_seen.front().has_value());
  for (const auto &deadline : nc.deadlines_seen) {
    EXPECT_EQ(deadline, nc.deadlines_seen.front());
  }
  EXPECT_FALSE(nc.io_deadline().has_value());
}

TEST(IOUtilsTest, ReconnectIsNotPartOfTheExchange) {
  // The reconnect takes 900 ms and the response about 135 ms: this fits in
  // the 1000 ms timeout only if the deadline starts after the reconnect.
  TricklingNetClient nc(1000, std::chrono::milliseconds(15));
  nc.connect_delay = std::chrono::milliseconds(900);
  nc.response_bytes = build_response_with_payload({0x42});
  kmipclient::IOUtils io(nc);
  kmipcore::secure_bytes response;

  io.do_exchange(std::vector<uint8_t>{0, 1, 2, 3}, response, 1024);
  EXPECT_EQ(response.size(), 9u);
  EXPECT_FALSE(nc.io_deadline().has_value());
}

TEST(IOUtilsTest, EarlierCallerDeadlineIsKeptAndRestored) {
  TricklingNetClient nc(5000, std::chrono::milliseconds(5));
  nc.response_bytes = build_response_with_payload(std::vector<uint8_t>(392));
  const auto caller_deadline =
      kmipclient::NetClient::Clock::now() + std::chrono::milliseconds(100);
  nc.set_io_deadline(caller_deadline);
  kmipclient::IOUtils io(nc);
  kmipcore::secure_bytes response;

  EXPECT_THROW(
      io.do_exchange(std::vector<uint8_t>{0, 1, 2, 3}, response, 1 << 20),
      kmipclient::KmipIOException
  );
  ASSERT_FALSE(nc.deadlines_seen.empty());
  EXPECT_EQ(nc.deadlines_seen.front(), caller_deadline);
  EXPECT_EQ(nc.io_deadline(), caller_deadline);
}

TEST(IOUtilsTest, TimeoutBoundsTheWholeSend) {
  // 400 bytes at 5 ms each take 2 s; every single send() is far below the
  // 200 ms timeout.
  TricklingNetClient nc(200, std::chrono::milliseconds(5));
  nc.trickle_send = true;
  nc.response_bytes = build_response_with_payload({0x42});
  kmipclient::IOUtils io(nc);

  const auto start = std::chrono::steady_clock::now();
  EXPECT_TRUE(contains(
      exchange_error(io, std::vector<uint8_t>(400, 0x42)),
      "KMIP send timed out: exchange deadline passed"
  ));
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(1));
}

TEST(IOUtilsTest, LastBytesAfterTheDeadlineAreRejected) {
  // Each recv() returns all it is asked for after 60 ms: the header at about
  // 60 ms, the body at about 120 ms, past the 100 ms deadline.
  TricklingNetClient nc(100, std::chrono::milliseconds(60));
  nc.whole_reads = true;
  nc.response_bytes = build_response_with_payload({0x42});
  kmipclient::IOUtils io(nc);

  EXPECT_TRUE(contains(
      exchange_error(io, std::vector<uint8_t>{0, 1, 2, 3}),
      "KMIP receive timed out: exchange deadline passed"
  ));
  EXPECT_FALSE(nc.is_connected());
}

TEST(IOUtilsTest, EmptyRequestIsRejectedBeforeReconnecting) {
  FakeNetClient nc;  // not connected
  nc.connect_result = false;
  kmipclient::IOUtils io(nc);

  EXPECT_TRUE(contains(
      exchange_error(io, std::vector<uint8_t>{}),
      "Can not send empty KMIP request."
  ));
  EXPECT_EQ(nc.connect_calls, 0);
}

TEST(IOUtilsTest, FailedReconnectEndsTheExchange) {
  FakeNetClient nc;  // not connected
  nc.connect_result = false;
  kmipclient::IOUtils io(nc);

  EXPECT_TRUE(contains(
      exchange_error(io, std::vector<uint8_t>{0, 1, 2, 3}),
      "Can not connect to the KMIP server."
  ));
  EXPECT_EQ(nc.connect_calls, 1);
  EXPECT_EQ(nc.send_calls, 0);
  EXPECT_EQ(nc.close_calls, 1);
  EXPECT_FALSE(nc.is_connected());
}

TEST(IOUtilsTest, WrapperThatForwardsIsConnectedIsNotReconnected) {
  FakeNetClient inner;
  const auto one = build_response_with_payload({0x42});
  for (int i = 0; i < 3; ++i) {
    inner.response_bytes.insert(
        inner.response_bytes.end(), one.begin(), one.end()
    );
  }
  ForwardingNetClient nc(inner);
  ASSERT_TRUE(nc.connect());
  kmipclient::IOUtils io(nc);

  for (int i = 0; i < 3; ++i) {
    EXPECT_EQ(exchange_error(io, std::vector<uint8_t>{0, 1, 2, 3}), "");
  }
  EXPECT_EQ(inner.connect_calls, 1);
}

TEST(IOUtilsTest, DebugLoggingRedactsSensitiveTtlvFields) {
  FakeNetClient nc;

  auto request = kmipcore::Element::createStructure(
      kmipcore::tag::KMIP_TAG_REQUEST_MESSAGE
  );
  request->asStructure()->add(
      kmipcore::Element::createTextString(
          kmipcore::tag::KMIP_TAG_USERNAME, "alice"
      )
  );
  request->asStructure()->add(
      kmipcore::Element::createTextString(
          kmipcore::tag::KMIP_TAG_PASSWORD, "s3cr3t"
      )
  );
  request->asStructure()->add(
      kmipcore::Element::createByteString(
          kmipcore::tag::KMIP_TAG_KEY_MATERIAL, {0xDE, 0xAD, 0xBE, 0xEF}
      )
  );
  const auto request_bytes = serialize_element(request);

  auto response = kmipcore::Element::createStructure(
      kmipcore::tag::KMIP_TAG_RESPONSE_MESSAGE
  );
  auto secret_data =
      kmipcore::Element::createStructure(kmipcore::tag::KMIP_TAG_SECRET_DATA);
  secret_data->asStructure()->add(
      kmipcore::Element::createEnumeration(
          kmipcore::tag::KMIP_TAG_SECRET_DATA_TYPE,
          static_cast<int32_t>(
              kmipcore::secret_data_type::KMIP_SECDATA_PASSWORD
          )
      )
  );
  response->asStructure()->add(secret_data);
  {
    const auto sb = serialize_element(response);
    nc.response_bytes.assign(sb.begin(), sb.end());
  }

  auto logger = std::make_shared<CollectingLogger>();
  kmipclient::IOUtils io(nc, logger);
  kmipcore::secure_bytes response_bytes;

  ASSERT_NO_THROW(io.do_exchange(request_bytes, response_bytes, 1024));
  ASSERT_EQ(logger->records.size(), 2u);

  const std::string combined =
      logger->records[0].message + "\n" + logger->records[1].message;
  EXPECT_NE(combined.find("Username"), std::string::npos);
  EXPECT_NE(combined.find("Password"), std::string::npos);
  EXPECT_NE(combined.find("KeyMaterial"), std::string::npos);
  EXPECT_NE(combined.find("SecretData"), std::string::npos);
  EXPECT_NE(combined.find("<redacted sensitive"), std::string::npos);
  EXPECT_EQ(combined.find("alice"), std::string::npos);
  EXPECT_EQ(combined.find("s3cr3t"), std::string::npos);
  EXPECT_EQ(combined.find("DE AD BE EF"), std::string::npos);
}

TEST(NetClientTest, TlsVerificationDefaultsToPeerAndHostnameEnabled) {
  FakeNetClient nc;

  const auto options = nc.tls_verification();
  EXPECT_TRUE(options.peer_verification);
  EXPECT_TRUE(options.hostname_verification);
}

TEST(NetClientTest, TlsVerificationCanBeUpdatedBeforeConnect) {
  FakeNetClient nc;

  nc.set_tls_verification({
      .peer_verification = true,
      .hostname_verification = false,
  });

  auto options = nc.tls_verification();
  EXPECT_TRUE(options.peer_verification);
  EXPECT_FALSE(options.hostname_verification);

  nc.set_tls_verification({
      .peer_verification = false,
      .hostname_verification = false,
  });

  options = nc.tls_verification();
  EXPECT_FALSE(options.peer_verification);
  EXPECT_FALSE(options.hostname_verification);
}

TEST(NetClientOpenSSLTest, TlsVerificationSettingsAreStoredOnTransport) {
  kmipclient::NetClientOpenSSL nc(
      "kmip.example.test", "5696", "client.pem", "client.key", "ca.pem", 1000
  );

  nc.set_tls_verification({
      .peer_verification = true,
      .hostname_verification = false,
  });

  const auto options = nc.tls_verification();
  EXPECT_TRUE(options.peer_verification);
  EXPECT_FALSE(options.hostname_verification);
}
