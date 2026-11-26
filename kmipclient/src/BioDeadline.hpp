/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_BIO_DEADLINE_HPP
#define KMIPCLIENT_BIO_DEADLINE_HPP

#include "kmipclient/NetClient.hpp"

#include <chrono>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <optional>

// Waiting on a non-blocking OpenSSL BIO against a deadline. Internal to
// NetClientOpenSSL; in a header only so that the tests can call it with a
// BIO double.
namespace kmipclient::detail {

  /**
   * Waits with poll() until the BIO can make progress, but not past
   * deadline. Throws KmipIOException when the deadline has already passed,
   * so a caller that retries the BIO call after every return is bounded by
   * it. Returns early when a signal interrupts the wait, and after at most
   * INT_MAX ms; the caller's retry then waits again for the time that is
   * left.
   * @param exchange_deadline the deadline is the one set around a
   *        request/response exchange (possibly by the caller), not now +
   *        timeout_ms; the message then does not quote timeout_ms.
   */
  void wait_for_bio_retry(
      BIO *bio,
      NetClient::Clock::time_point deadline,
      const char *op,
      int timeout_ms,
      bool exchange_deadline = false
  );

  /**
   * Runs io() (a BIO_read() or BIO_write() on the non-blocking bio) until it
   * makes progress or fails, waiting between attempts no longer than
   * io_deadline, or than timeout_ms from now when it is not set. This bounds
   * the call however slowly the peer sends or reads, also while OpenSSL
   * assembles one TLS record from many socket reads. With timeout_ms <= 0
   * the socket is blocking and io() runs once.
   *
   * Clears the thread's OpenSSL error queue before each attempt, so that
   * the caller can inspect the errors of a failed one.
   */
  template<typename Io>
  int io_with_deadline(
      BIO *bio,
      std::optional<NetClient::Clock::time_point> io_deadline,
      int timeout_ms,
      const char *op,
      Io &&io
  ) {
    if (timeout_ms <= 0) {
      return io();  // blocking socket, no timeout
    }
    const auto deadline = io_deadline.value_or(
        NetClient::Clock::now() + std::chrono::milliseconds(timeout_ms)
    );
    for (;;) {
      ERR_clear_error();
      const int ret = io();
      // A retry that waits for neither reading nor writing is not expected
      // after the handshake; report it instead of polling until the
      // deadline.
      if (ret > 0 || !BIO_should_retry(bio) ||
          (!BIO_should_read(bio) && !BIO_should_write(bio))) {
        return ret;
      }
      wait_for_bio_retry(
          bio, deadline, op, timeout_ms, io_deadline.has_value()
      );
    }
  }

}  // namespace kmipclient::detail

#endif  // KMIPCLIENT_BIO_DEADLINE_HPP
