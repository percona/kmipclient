/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */
#ifndef KMIPCLIENT_KMIP_CLIENT_POOL_HPP
#define KMIPCLIENT_KMIP_CLIENT_POOL_HPP

#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace kmipclient {

  /**
   * Thread-safe pool of KmipClient connections.
   *
   * Each thread borrows a KmipClient for the duration of one or more KMIP
   * operations and then returns it automatically via RAII.  The pool creates
   * new TLS connections on demand, up to max_connections.  When all connections
   * are in use and the limit has been reached, borrow() blocks until one
   * becomes available.
   *
   * Typical usage:
   * @code
   *   KmipClientPool pool({
   *       .host = "kmip-server",
   *       .port = "5696",
   *       .client_cert = "/path/to/cert.pem",
   *       .client_key  = "/path/to/key.pem",
   *       .server_ca_cert = "/path/to/ca.pem",
   *       .timeout_ms  = 5000,
   *       .max_connections = 8
   *   });
   *
   *   // In any thread:
   *   auto conn = pool.borrow();
   *   auto id   = conn->op_create_aes_key("mykey", "mygroup");
   *   // conn is returned to the pool automatically when it goes out of scope.
   * @endcode
   */
  class KmipClientPool {
  private:
    // ---- Slot
    // ------------------------------------------------------------------ One
    // "slot" = one TLS connection + one KmipClient bound to that connection.
    // Slots are heap-allocated so that the KmipClient's reference to NetClient
    // stays valid even if the unique_ptr to the Slot is moved around.
    struct Slot {
      std::unique_ptr<NetClientOpenSSL> net_client;
      std::unique_ptr<KmipClient> kmip_client;
    };

  public:
    // ---- Constants
    // -------------------------------------------------------------

    /** Default upper bound for simultaneously open KMIP connections. */
    static constexpr size_t DEFAULT_MAX_CONNECTIONS = 16;

    // ---- Config
    // ----------------------------------------------------------------

    /**
     * @brief Connection and pooling settings used to construct @ref
     * KmipClientPool.
     */
    struct Config {
      /** KMIP server host name or IP address. */
      std::string host;
      /** KMIP server service port. */
      std::string port;
      std::string client_cert;     ///< Path to PEM client certificate
      std::string client_key;      ///< Path to PEM client private key
      std::string server_ca_cert;  ///< Path to PEM server CA certificate (or
                                   ///< server cert)
      std::shared_ptr<kmipcore::Logger>
          logger;  ///< Optional KMIP protocol logger
      /** Timeout in milliseconds for connecting (TCP and TLS together) and
       * for each request/response exchange as a whole. */
      int timeout_ms = 5000;
      /** Maximum number of simultaneous live connections in the pool. */
      size_t max_connections = DEFAULT_MAX_CONNECTIONS;
      /** KMIP protocol version used by all connections in the pool. */
      kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4;
      /** TLS peer/hostname verification settings applied to each pooled
       * transport. */
      NetClient::TlsVerificationOptions tls_verification{};
    };

    // ---- BorrowedClient
    // --------------------------------------------------------

    /**
     * RAII guard wrapping a single borrowed connection.
     *
     * Provides KmipClient access via operator* / operator->.
     * Automatically returns the connection to the pool on destruction.
     *
     * If the KMIP operation threw an exception, call markUnhealthy() before
     * the guard goes out of scope so the pool discards the connection instead
     * of re-using it.
     */
    class BorrowedClient {
    public:
      ~BorrowedClient();

      // Non-copyable (unique ownership of the borrowed slot)
      BorrowedClient(const BorrowedClient &) = delete;
      BorrowedClient &operator=(const BorrowedClient &) = delete;

      // Movable (e.g. return from a factory function)
      BorrowedClient(BorrowedClient &&) noexcept;
      BorrowedClient &operator=(BorrowedClient &&) noexcept;

      /** @brief Accesses the borrowed client as a reference. */
      KmipClient &operator*();
      /** @brief Accesses the borrowed client as a pointer. */
      KmipClient *operator->();

      /**
       * Mark this connection as unhealthy.
       * When the BorrowedClient is destroyed the pool will close and discard
       * this connection (freeing one slot for a fresh connection next time).
       *
       * Call this whenever a KMIP operation throws an exception you cannot
       * recover from on the same connection.
       */
      void markUnhealthy() noexcept { healthy_ = false; }

      /// Returns false if markUnhealthy() has been called.
      [[nodiscard]] bool isHealthy() const noexcept { return healthy_; }

    private:
      friend class KmipClientPool;

      BorrowedClient(KmipClientPool &pool, std::unique_ptr<Slot> slot) noexcept;

      KmipClientPool *pool_ =
          nullptr;  ///< non-owning; pool outlives any borrow
      std::unique_ptr<Slot> slot_;
      bool healthy_ = true;
    };

    // ---- Construction / destruction
    // --------------------------------------------

    /**
     * Construct the pool.  No connections are created immediately; they are
     * established lazily on the first borrow() call.
     *
     * @throws kmipcore::KmipException if max_connections == 0
     */
    explicit KmipClientPool(const Config &config);
    ~KmipClientPool() = default;

    // Non-copyable, non-movable (holds a mutex and a condition_variable)
    KmipClientPool(const KmipClientPool &) = delete;
    KmipClientPool &operator=(const KmipClientPool &) = delete;
    KmipClientPool(KmipClientPool &&) = delete;
    KmipClientPool &operator=(KmipClientPool &&) = delete;

    // ---- Borrow methods
    // --------------------------------------------------------

    /**
     * Borrow a client, blocking indefinitely until one is available.
     *
     * If the pool is below max_connections a new TLS connection is created
     * on demand.  If the pool is at capacity the call blocks until another
     * thread returns a connection.
     *
     * @throws kmipcore::KmipException if a new connection must be created and
     *         the TLS handshake fails.
     */
    [[nodiscard]] BorrowedClient borrow();

    /**
     * Like borrow(), but gives up after @p timeout.
     *
     * @throws kmipcore::KmipException on timeout or TLS connection failure.
     */
    [[nodiscard]] BorrowedClient borrow(std::chrono::milliseconds timeout);

    /**
     * Non-blocking variant.
     *
     * Returns std::nullopt immediately when no connection is available and the
     * pool is at capacity.  Otherwise behaves like borrow().
     *
     * @throws kmipcore::KmipException if a new connection must be created and
     *         the TLS handshake fails.
     */
    [[nodiscard]] std::optional<BorrowedClient> try_borrow();

    // ---- Diagnostic accessors
    // --------------------------------------------------

    /// Number of connections currently idle in the pool.
    [[nodiscard]] size_t available_count() const;

    /// Total connections in existence (idle + currently borrowed).
    [[nodiscard]] size_t total_count() const;

    /// Configured upper limit.
    [[nodiscard]] size_t max_connections() const noexcept {
      return config_.max_connections;
    }

  private:
    // ---- Internal helpers
    // ------------------------------------------------------

    /// Create a brand-new connected Slot.  Called without the lock held.
    /// Throws on TLS handshake failure.
    std::unique_ptr<Slot> create_slot();

    /// Return a slot to the pool (or discard it if unhealthy / disconnected).
    /// safe to call from BorrowedClient destructor (noexcept).
    void return_slot(std::unique_ptr<Slot> slot, bool healthy) noexcept;

    /// Acquire one slot with the lock already held (and still locked via lk).
    /// Unlocks lk before the potentially slow TLS connect call.
    BorrowedClient acquire_locked(std::unique_lock<std::mutex> lk);

    // ---- Data members
    // ----------------------------------------------------------

    Config config_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;

    /// Idle (available) connections.
    std::vector<std::unique_ptr<Slot>> available_;

    /// Total connections created and not yet destroyed (available + in-use).
    size_t total_count_ = 0;
  };

}  // namespace kmipclient

#endif /* KMIPCLIENT_KMIP_CLIENT_POOL_HPP */
