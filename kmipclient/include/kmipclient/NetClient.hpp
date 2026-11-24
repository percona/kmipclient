/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIP_NET_CLIENT_HPP
#define KMIP_NET_CLIENT_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace kmipclient {

  /**
   * @brief Abstract transport interface used by @ref KmipClient.
   *
   * Implementations provide connection lifecycle and raw byte send/receive
   * primitives over a secure channel.
   */
  class NetClient {
  public:
    /**
     * @brief TLS certificate-verification settings applied on the next
     * connect().
     *
     * Hostname verification is meaningful only when peer verification is also
     * enabled. Implementations may reject the invalid combination
     * {peer_verification=false, hostname_verification=true}.
     */
    struct TlsVerificationOptions {
      bool peer_verification = true;
      bool hostname_verification = true;
    };

    /**
     * @brief Stores transport configuration.
     * @param host KMIP server host.
     * @param port KMIP server port.
     * @param clientCertificateFn Path to client X.509 certificate in PEM.
     * @param clientKeyFn Path to matching client private key in PEM.
     * @param serverCaCertFn Path to trusted server CA/certificate in PEM.
     * @param timeout_ms Timeout in milliseconds for the TCP connect and TLS
     *        handshake together, and for each request/response exchange as a
     *        whole (see @ref set_io_deadline). Non-positive values mean no
     *        explicit timeout is enforced by this layer.
     */
    NetClient(
        const std::string &host,
        const std::string &port,
        const std::string &clientCertificateFn,
        const std::string &clientKeyFn,
        const std::string &serverCaCertFn,
        int timeout_ms
    ) noexcept
      : m_host(host),
        m_port(port),
        m_clientCertificateFn(clientCertificateFn),
        m_clientKeyFn(clientKeyFn),
        m_serverCaCertificateFn(serverCaCertFn),
        m_timeout_ms(timeout_ms) {}

    /** @brief Virtual destructor for interface-safe cleanup. */
    virtual ~NetClient() = default;
    // no copy, no move
    NetClient(const NetClient &) = delete;
    NetClient &operator=(const NetClient &) = delete;
    NetClient(NetClient &&) = delete;
    NetClient &operator=(NetClient &&) = delete;

    /**
     * @brief Establishes network/TLS connection to the KMIP server.
     *        Must honor @ref m_timeout_ms for connect + handshake phases.
     * @return true on successful connection establishment, false otherwise.
     */
    virtual bool connect() = 0;
    /** @brief Closes the connection and releases underlying resources. */
    virtual void close() = 0;

    /**
     * @brief Updates TLS peer/hostname verification settings for future
     * connect() calls.
     *
     * Changing these options does not affect an already-established TLS
     * session; disconnect and reconnect for the new settings to take effect.
     */
    virtual void set_tls_verification(TlsVerificationOptions options) noexcept {
      m_tls_verification = options;
    }

    /** @brief Returns the TLS verification settings currently configured on
     * this transport. */
    [[nodiscard]] virtual TlsVerificationOptions
        tls_verification() const noexcept {
      return m_tls_verification;
    }

    /**
     * @brief Checks whether a connection is currently established.
     * @return true when connected, false otherwise.
     */
    [[nodiscard]] bool is_connected() const noexcept { return m_isConnected; }

    /** @brief Clock of @ref set_io_deadline. */
    using Clock = std::chrono::steady_clock;

    /** @brief Returns the timeout given to the constructor. */
    [[nodiscard]] int timeout_ms() const noexcept { return m_timeout_ms; }

    /**
     * @brief Sets a point in time that @ref send and @ref recv must not block
     *        past, until it is cleared with std::nullopt.
     *
     * The client sets it around each request/response exchange to now +
     * timeout_ms, or to an earlier deadline already set here, and restores
     * the previous value afterwards. So timeout_ms bounds the exchange as a
     * whole, however the peer spreads its bytes over time. Implementations
     * throw KmipIOException when the deadline passes. Without a deadline,
     * each call is bounded by timeout_ms on its own. NetClientOpenSSL honours
     * the deadline only with a positive timeout_ms (otherwise its socket is
     * blocking).
     *
     * A NetClient that wraps another one should pass the same timeout_ms to
     * its base and override this to call NetClient::set_io_deadline() and
     * then forward the deadline to the wrapped client.
     */
    virtual void
        set_io_deadline(std::optional<Clock::time_point> deadline) noexcept {
      m_io_deadline = deadline;
    }

    /** @brief Returns the deadline set by @ref set_io_deadline, if any. */
    [[nodiscard]] std::optional<Clock::time_point>
        io_deadline() const noexcept {
      return m_io_deadline;
    }

    /**
     * @brief Sends bytes over the established connection.
     * @param data Source buffer.
     * @return Number of bytes sent, or -1 on failure.
     */
    virtual int send(std::span<const std::uint8_t> data) = 0;

    /**
     * @brief Receives bytes from the established connection.
     * @param data Destination buffer.
     * @return Number of bytes received, or -1 on failure.
     */
    virtual int recv(std::span<std::uint8_t> data) = 0;

  protected:
    std::string m_host;
    std::string m_port;
    std::string m_clientCertificateFn;
    std::string m_clientKeyFn;
    std::string m_serverCaCertificateFn;
    int m_timeout_ms;
    std::optional<Clock::time_point> m_io_deadline;
    TlsVerificationOptions m_tls_verification{};
    std::atomic<bool> m_isConnected{false};
  };

}  // namespace kmipclient

#endif  // KMIP_NET_CLIENT_HPP
