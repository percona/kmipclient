/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIP_HPP
#define KMIP_HPP

#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
#include "kmipcore/kmip_protocol.hpp"

#include <memory>

namespace kmipclient {

  /**
   * @brief Convenience wrapper that owns transport and client instances.
   *
   * This class builds and connects @ref NetClientOpenSSL and then exposes
   * the initialized @ref KmipClient instance.  Can be used as either a
   * value-based facade (stack-allocated) or wrapped in std::shared_ptr for
   * shared ownership across threads/scopes.
   *
   * Lifetime semantics:
   * - When stack-allocated: transport closes on scope exit (destructor).
   * - When shared via std::shared_ptr: transport closes when last handle goes
   * away.
   * - Can be moved to transfer ownership; copy is deleted for clarity.
   */
  class Kmip {
  public:
    /**
     * @brief Creates and connects an OpenSSL-based KMIP client stack.
     * @param host KMIP server hostname or IP address.
     * @param port KMIP server port.
     * @param clientCertificateFn Path to client X.509 certificate in PEM.
     * @param clientKeyFn Path to client private key in PEM.
     * @param serverCaCertFn Path to trusted server CA/certificate in PEM.
     * @param timeout_ms Connect/read/write timeout in milliseconds.
     * @param version KMIP protocol version to use for requests.
     * @param logger Optional KMIP protocol logger.
     * @param tls_verification TLS peer/hostname verification settings applied
     *        before the OpenSSL transport connects.
     * @param close_on_destroy When true (default), closes the transport on
     *        Kmip destruction. Set to false to keep transport alive after
     *        Kmip destruction.
     * @throws kmipcore::KmipException when network/TLS initialization fails.
     */
    Kmip(
        const char *host,
        const char *port,
        const char *clientCertificateFn,
        const char *clientKeyFn,
        const char *serverCaCertFn,
        int timeout_ms,
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        NetClient::TlsVerificationOptions tls_verification = {false, false},
        bool close_on_destroy = true
    )
      : m_net_client(
            std::make_shared<NetClientOpenSSL>(
                host,
                port,
                clientCertificateFn,
                clientKeyFn,
                serverCaCertFn,
                timeout_ms,
                tls_verification
            )
        ),
        m_client(m_net_client, logger, version, close_on_destroy) {
      m_net_client->connect();
    }

    /**
     * @brief Destroys the facade, closing the transport if close_on_destroy is
     * true.
     * @see set_close_on_destroy()
     */
    ~Kmip() = default;

    // Movable (transfer ownership of transport and client)
    Kmip(Kmip &&) noexcept = default;
    Kmip &operator=(Kmip &&) noexcept = default;

    // Non-copyable (for clarity: shared ownership should use
    // std::shared_ptr<Kmip>)
    Kmip(const Kmip &) = delete;
    Kmip &operator=(const Kmip &) = delete;

    /**
     * @brief Returns the initialized high-level KMIP client.
     * @return Mutable reference to the owned @ref KmipClient.
     */
    KmipClient &client() { return m_client; }

    /**
     * @brief Returns const reference to the client.
     */
    [[nodiscard]] const KmipClient &client() const { return m_client; }

    /**
     * @brief Returns reference to the underlying transport.
     * Use with care; generally prefer client() for KMIP operations.
     */
    NetClientOpenSSL &transport() { return *m_net_client; }

    /**
     * @brief Returns const reference to the underlying transport.
     */
    [[nodiscard]] const NetClientOpenSSL &transport() const {
      return *m_net_client;
    }

    /**
     * @brief Queries the close_on_destroy setting.
     * @return true if the transport will be closed on Kmip destruction,
     *         false if the transport will remain open.
     */
    [[nodiscard]] bool close_on_destroy() const noexcept {
      return m_client.close_on_destroy();
    }

    /**
     * @brief Factory for shared-handle based usage.
     * Returns std::shared_ptr<Kmip> for scenarios where multiple threads
     * or components need to share the client handle.
     *
     * Example (multi-threaded):
     * @code
     *   auto kmip = Kmip::create_shared(host, port, cert, key, ca, 5000);
     *   // Pass kmip to multiple threads; each keeps a shared_ptr copy
     *   // Transport is closed when the last shared_ptr is destroyed
     * @endcode
     */
    [[nodiscard]] static std::shared_ptr<Kmip> create_shared(
        const char *host,
        const char *port,
        const char *clientCertificateFn,
        const char *clientKeyFn,
        const char *serverCaCertFn,
        int timeout_ms,
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        NetClient::TlsVerificationOptions tls_verification = {false, false},
        bool close_on_destroy = true
    ) {
      return std::make_shared<Kmip>(
          host,
          port,
          clientCertificateFn,
          clientKeyFn,
          serverCaCertFn,
          timeout_ms,
          version,
          logger,
          tls_verification,
          close_on_destroy
      );
    }

  private:
    /** @brief OpenSSL BIO-based network transport. */
    std::shared_ptr<NetClientOpenSSL> m_net_client;
    /** @brief High-level KMIP protocol client bound to @ref m_net_client. */
    KmipClient m_client;
  };

}  // namespace kmipclient

#endif  // KMIP_HPP
