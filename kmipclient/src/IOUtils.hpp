/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef IOUTILS_HPP
#define IOUTILS_HPP

#include "kmipclient/NetClient.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_logger.hpp"
#include "kmipcore/secure_memory.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace kmipclient {

  class IOUtils {
  public:
    explicit IOUtils(
        NetClient &nc, const std::shared_ptr<kmipcore::Logger> &logger = {}
    )
      : net_client(nc), logger_(logger) {}

    void do_exchange(
        std::span<const uint8_t> request_bytes,
        kmipcore::secure_bytes &response_bytes,
        size_t max_message_size
    );

  private:
    void log_debug(const char *event, std::span<const uint8_t> ttlv) const;
    void send(std::span<const uint8_t> request_bytes) const;
    kmipcore::secure_bytes receive_message(size_t max_message_size);

    /**
     * Reads exactly n bytes from the network into the buffer.
     * Throws KmipException on error or prematureEOF.
     */
    void read_exact(std::span<uint8_t> buf);

    NetClient &net_client;
    std::shared_ptr<kmipcore::Logger> logger_;
  };

}  // namespace kmipclient

#endif  // IOUTILS_HPP
