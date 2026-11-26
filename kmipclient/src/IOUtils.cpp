/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "IOUtils.hpp"

#include "kmipclient/KmipIOException.hpp"
#include "kmipcore/kmip_formatter.hpp"
#include "kmipcore/kmip_logger.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <sstream>

namespace kmipclient {
#define KMIP_MSG_LENGTH_BYTES 8

  namespace {

    [[nodiscard]] int32_t read_int32_be(std::span<const uint8_t> bytes) {
      return (static_cast<int32_t>(bytes[0]) << 24) |
             (static_cast<int32_t>(bytes[1]) << 16) |
             (static_cast<int32_t>(bytes[2]) << 8) |
             static_cast<int32_t>(bytes[3]);
    }

    // Sets the exchange deadline on the connection, keeping an earlier one
    // the caller set, and restores the previous value on every way out of
    // the exchange.
    class ExchangeDeadline {
    public:
      explicit ExchangeDeadline(NetClient &nc)
        : nc_(nc), previous_(nc.io_deadline()) {
        if (nc_.timeout_ms() > 0) {
          auto deadline = NetClient::Clock::now() +
                          std::chrono::milliseconds(nc_.timeout_ms());
          if (previous_ && *previous_ < deadline) {
            deadline = *previous_;
          }
          nc_.set_io_deadline(deadline);
        }
      }
      ~ExchangeDeadline() { nc_.set_io_deadline(previous_); }
      ExchangeDeadline(const ExchangeDeadline &) = delete;
      ExchangeDeadline &operator=(const ExchangeDeadline &) = delete;

    private:
      NetClient &nc_;
      std::optional<NetClient::Clock::time_point> previous_;
    };

  }  // namespace

  void IOUtils::check_deadline(const char *op) const {
    // NetClientOpenSSL also bounds each call by the deadline; this check
    // covers NetClient implementations that only bound a single call.
    const auto deadline = net_client.io_deadline();
    if (deadline && NetClient::Clock::now() >= *deadline) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          std::string("KMIP ") + op + " timed out: exchange deadline passed"
      );
    }
  }

  void IOUtils::log_debug(
      const char *event, std::span<const uint8_t> ttlv
  ) const {
    try {
      if (!logger_ || !logger_->shouldLog(kmipcore::LogLevel::Debug)) {
        return;
      }

      logger_->log(
          kmipcore::LogRecord{
              .level = kmipcore::LogLevel::Debug,
              .component = "kmip.protocol",
              .event = event,
              .message = kmipcore::format_ttlv(ttlv)
          }
      );
    } catch (...) {
      // Logging is strictly best-effort: protocol operations must not fail
      // because a custom logger threw.
    }
  }

  void IOUtils::send(std::span<const uint8_t> request_bytes) const {
    const int dlen = static_cast<int>(request_bytes.size());
    int total_sent = 0;
    while (total_sent < dlen) {
      check_deadline("send");
      const int sent = net_client.send(
          request_bytes.subspan(static_cast<size_t>(total_sent))
      );
      if (sent <= 0) {
        std::ostringstream oss;
        oss << "Can not send request. Bytes total: " << dlen
            << ", bytes sent: " << total_sent;
        throw KmipIOException(kmipcore::KMIP_IO_FAILURE, oss.str());
      }
      total_sent += sent;
    }
  }

  void IOUtils::read_exact(std::span<uint8_t> buf) {
    int total_read = 0;
    const int n = static_cast<int>(buf.size());
    while (total_read < n) {
      check_deadline("receive");
      const int received =
          net_client.recv(buf.subspan(static_cast<size_t>(total_read)));
      if (received <= 0) {
        std::ostringstream oss;
        oss << "Connection closed or error while reading. Expected " << n
            << ", got " << total_read;
        throw KmipIOException(kmipcore::KMIP_IO_FAILURE, oss.str());
      }
      total_read += received;
    }
    // A NetClient that bounds only single calls may return the last bytes
    // after the deadline.
    check_deadline("receive");
  }

  kmipcore::secure_bytes IOUtils::receive_message(size_t max_message_size) {
    std::array<uint8_t, KMIP_MSG_LENGTH_BYTES> msg_len_buf{};

    read_exact(msg_len_buf);

    const int32_t length = read_int32_be(std::span(msg_len_buf).subspan(4, 4));
    const std::size_t effective_limit =
        std::min(max_message_size, kmipcore::KMIP_MAX_MESSAGE_HARD_LIMIT);
    if (length < 0 || static_cast<size_t>(length) > effective_limit) {
      std::ostringstream oss;
      oss << "Message too long. Length: " << length
          << ", allowed: " << effective_limit;
      throw KmipIOException(kmipcore::KMIP_EXCEED_MAX_MESSAGE_SIZE, oss.str());
    }

    kmipcore::secure_bytes response(
        KMIP_MSG_LENGTH_BYTES + static_cast<size_t>(length)
    );
    memcpy(response.data(), msg_len_buf.data(), KMIP_MSG_LENGTH_BYTES);

    read_exact(
        std::span(response).subspan(
            KMIP_MSG_LENGTH_BYTES, static_cast<size_t>(length)
        )
    );

    return response;
  }

  void IOUtils::do_exchange(
      std::span<const uint8_t> request_bytes,
      kmipcore::secure_bytes &response_bytes,
      size_t max_message_size
  ) {
    try {
      log_debug("request", request_bytes);
      if (request_bytes.empty()) {
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE, "Can not send empty KMIP request."
        );
      }
      // Reconnecting after an earlier failure has its own timeout_ms and is
      // not part of the exchange.
      if (!net_client.is_connected() && !net_client.connect()) {
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE, "Can not connect to the KMIP server."
        );
      }
      {
        const ExchangeDeadline deadline(net_client);
        send(request_bytes);
        response_bytes = receive_message(max_message_size);
      }
      log_debug("response", response_bytes);
    } catch (const KmipIOException &) {
      // Mark the underlying connection as dead so the pool (via
      // return_slot → is_connected() check) discards this slot
      // automatically — no need for the caller to call markUnhealthy().
      net_client.close();
      throw;
    }
  }

}  // namespace kmipclient
