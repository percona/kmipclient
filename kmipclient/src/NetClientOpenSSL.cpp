/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/NetClientOpenSSL.hpp"

#include "kmipclient/KmipIOException.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <sstream>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <fcntl.h>
  #include <poll.h>
  #include <sys/socket.h>
  #include <sys/time.h>
#endif

namespace kmipclient {

  // Replaces get_openssl_error using Queue
  static std::string getOpenSslError() {
    std::ostringstream oss;
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
      char buf[256];
      ERR_error_string_n(err, buf, sizeof(buf));
      oss << buf << "; ";
    }
    std::string errStr = oss.str();
    if (errStr.empty()) {
      return "Unknown OpenSSL error";
    }
    return errStr;
  }

#ifdef _WIN32
  static int last_socket_error() {
    return WSAGetLastError();
  }
  static void clear_socket_error() {
    WSASetLastError(0);
  }
  static std::string socket_error_string(int err) {
    char buf[256] = {};
    const DWORD len = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(err),
        0,
        buf,
        sizeof(buf),
        nullptr
    );
    std::string msg(buf, len);
    while (!msg.empty() &&
           (msg.back() == '\r' || msg.back() == '\n' || msg.back() == ' ')) {
      msg.pop_back();
    }
    if (msg.empty()) {
      return "Winsock error " + std::to_string(err);
    }
    return msg;
  }
  // WSAETIMEDOUT: SO_RCVTIMEO/SO_SNDTIMEO expired. WSAEWOULDBLOCK is the
  // Windows analogue of EAGAIN on a socket with a pending timeout.
  static bool is_timeout_socket_error(int err) {
    return err == WSAETIMEDOUT || err == WSAEWOULDBLOCK;
  }
#else
  static int last_socket_error() {
    return errno;
  }
  static void clear_socket_error() {
    errno = 0;
  }
  static std::string socket_error_string(int err) {
    return strerror(err);
  }
  static bool is_timeout_socket_error(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT;
  }
#endif

  static std::string timeoutMessage(const char *op, int timeout_ms) {
    std::ostringstream oss;
    oss << "KMIP " << op << " timed out after " << timeout_ms << "ms";
    return oss.str();
  }

  // a2i_IPADDRESS is a pure parser (accepts IPv4 dotted-quad and IPv6),
  // so this works before Winsock is initialized on Windows.
  static bool is_ip_address(const std::string &host) {
    ASN1_OCTET_STRING *addr = a2i_IPADDRESS(host.c_str());
    if (addr == nullptr) {
      return false;
    }
    ASN1_OCTET_STRING_free(addr);
    return true;
  }

  // TLS_method() was introduced in OpenSSL 1.1.0.
  // Older builds (OpenSSL < 1.1.0) use the SSLv23_method() alias.
  static const SSL_METHOD *get_tls_client_method() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    return SSLv23_method();
#else
    return TLS_method();
#endif
  }

  // SSL_get0_peer_certificate() (borrowed ref, no X509_free needed) was
  // introduced in OpenSSL 3.0.  OpenSSL 1.0.x and 1.1.x — including the
  // OpenSSL 1.1.1 shipped with Oracle Linux 8 — only have
  // SSL_get_peer_certificate() which bumps the refcount and requires X509_free.
  static X509 *get_peer_certificate(SSL *ssl) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
    return SSL_get0_peer_certificate(ssl);
#else
    return SSL_get_peer_certificate(ssl);
#endif
  }

  static void configure_tls_verification(
      SSL_CTX *ctx,
      SSL *ssl,
      const std::string &host,
      const NetClient::TlsVerificationOptions &options
  ) {
    if (options.hostname_verification && !options.peer_verification) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "TLS hostname verification requires TLS peer verification to be "
          "enabled"
      );
    }

    SSL_CTX_set_verify(
        ctx,
        options.peer_verification ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
        nullptr
    );

    if (host.empty()) {
      // The context-level call passes no SSL and no host on purpose. For a
      // connection, connect() has already refused an empty host; this keeps
      // a requested host name check from being skipped silently.
      if (ssl != nullptr && options.hostname_verification) {
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE,
            "TLS hostname verification requested, but no host name was given"
        );
      }
      return;
    }

    const bool host_is_ip = is_ip_address(host);
    if (!host_is_ip) {
      if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) {
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE,
            "Failed to configure TLS SNI for host '" + host +
                "': " + getOpenSslError()
        );
      }
    }

    if (!options.peer_verification || !options.hostname_verification) {
      return;
    }

    if (host_is_ip) {
      // For IP-literal hosts, check IP SANs in the server certificate.
      // SNI is not applicable to IP addresses.
      // Use X509_VERIFY_PARAM_set1_ip_asc so OpenSSL compares the connecting
      // IP against iPAddress SAN entries. Connections to servers whose
      // certificates carry no matching IP SAN will fail; use
      // hostname_verification=false to suppress this check (e.g. dev/lab
      // environments that issue certs for a DNS name but are reached by IP).
      X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
      if (X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str()) != 1) {
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE,
            "Failed to configure TLS IP verification for '" + host +
                "': " + getOpenSslError()
        );
      }
      return;
    }

    if (SSL_set1_host(ssl, host.c_str()) != 1) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "Failed to configure TLS hostname verification for '" + host +
              "': " + getOpenSslError()
      );
    }
  }

  static void ensure_tls_peer_verified(
      SSL *ssl, const NetClient::TlsVerificationOptions &options
  ) {
    if (!options.peer_verification) {
      return;
    }

    X509 *peer_cert = get_peer_certificate(ssl);
    if (peer_cert == nullptr) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "TLS peer verification failed: server did not present a certificate"
      );
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
    // SSL_get_peer_certificate() bumps the refcount; release the reference.
    X509_free(peer_cert);
#endif

    const long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "TLS peer verification failed: " +
              std::string(X509_verify_cert_error_string(verify_result))
      );
    }
  }

  // Waits until the SSL BIO can make forward progress, bounded by deadline.
  static void wait_for_bio_retry(
      BIO *bio,
      const std::chrono::steady_clock::time_point &deadline,
      const char *op,
      int timeout_ms
  ) {
    int fd = -1;
    if (BIO_get_fd(bio, &fd) < 0 || fd < 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          std::string("Unable to obtain socket while waiting for ") + op
      );
    }

    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE, timeoutMessage(op, timeout_ms)
      );
    }

    auto remaining_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
            .count();
    if (remaining_ms <= 0) {
      remaining_ms = 1;
    }

#ifdef _WIN32
    WSAPOLLFD pfd{};
    pfd.fd = static_cast<SOCKET>(fd);
#else
    struct pollfd pfd{};
    pfd.fd = fd;
#endif
    if (BIO_should_read(bio)) {
      pfd.events |= POLLIN;
    }
    if (BIO_should_write(bio)) {
      pfd.events |= POLLOUT;
    }
    if (pfd.events == 0) {
      pfd.events = POLLIN | POLLOUT;
    }

    int poll_ret = 0;
#ifdef _WIN32
    poll_ret = WSAPoll(&pfd, 1, static_cast<int>(remaining_ms));
#else
    do {
      poll_ret = poll(&pfd, 1, static_cast<int>(remaining_ms));
    } while (poll_ret < 0 && errno == EINTR);
#endif

    if (poll_ret == 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE, timeoutMessage(op, timeout_ms)
      );
    }
    if (poll_ret < 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          std::string("poll failed while waiting for ") + op + ": " +
              socket_error_string(last_socket_error())
      );
    }
  }

  static void restore_socket_blocking(BIO *bio) {
    int fd = -1;
    if (BIO_get_fd(bio, &fd) < 0 || fd < 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "Unable to obtain socket fd for mode switch"
      );
    }

#ifdef _WIN32
    u_long blocking_mode = 0;
    if (ioctlsocket(static_cast<SOCKET>(fd), FIONBIO, &blocking_mode) != 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "ioctlsocket(FIONBIO) failed: " +
              socket_error_string(last_socket_error())
      );
    }
#else
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          std::string("fcntl(F_GETFL) failed: ") +
              socket_error_string(last_socket_error())
      );
    }

    const int desired_flags = flags & ~O_NONBLOCK;
    if (fcntl(fd, F_SETFL, desired_flags) != 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          std::string("fcntl(F_SETFL) failed: ") +
              socket_error_string(last_socket_error())
      );
    }
#endif
  }

  // Apply SO_RCVTIMEO / SO_SNDTIMEO on the underlying socket so that every
  // BIO_read / BIO_write call times out after timeout_ms milliseconds.
  // Must be called after BIO_do_connect() succeeds.
  static void apply_socket_io_timeout(BIO *bio, int timeout_ms) {
    if (timeout_ms <= 0) {
      return;
    }

    int fd = -1;
    if (BIO_get_fd(bio, &fd) < 0 || fd < 0) {
      // Unable to obtain socket fd – skip silently (non-fatal).
      return;
    }

#ifdef _WIN32
    const DWORD tv = static_cast<DWORD>(timeout_ms);
    const SOCKET sock = static_cast<SOCKET>(fd);
#else
    struct timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int sock = fd;
#endif

    if (setsockopt(
            sock,
            SOL_SOCKET,
            SO_RCVTIMEO,
            reinterpret_cast<const char *>(&tv),
            sizeof(tv)
        ) != 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "Failed to set SO_RCVTIMEO (" + std::to_string(timeout_ms) +
              "ms): " + socket_error_string(last_socket_error())
      );
    }
    if (setsockopt(
            sock,
            SOL_SOCKET,
            SO_SNDTIMEO,
            reinterpret_cast<const char *>(&tv),
            sizeof(tv)
        ) != 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "Failed to set SO_SNDTIMEO (" + std::to_string(timeout_ms) +
              "ms): " + socket_error_string(last_socket_error())
      );
    }
  }

  bool NetClientOpenSSL::checkConnected() {
    if (is_connected()) {
      return true;
    }
    return connect();
  }

  NetClientOpenSSL::NetClientOpenSSL(
      const std::string &host,
      const std::string &port,
      const std::string &clientCertificateFn,
      const std::string &clientKeyFn,
      const std::string &serverCaCertFn,
      int timeout_ms,
      TlsVerificationOptions tls_verification
  )
    : NetClient(
          host,
          port,
          clientCertificateFn,
          clientKeyFn,
          serverCaCertFn,
          timeout_ms
      ) {
    m_tls_verification = tls_verification;
  }

  NetClientOpenSSL::~NetClientOpenSSL() {
    close();
  }

  // The server host in the two forms connect() needs.
  struct ServerHost {
    // For the certificate check and SNI: a DNS name or an IP address.
    std::string name;
    // For BIO_set_conn_hostname(): the name, with an IPv6 address in
    // brackets, so that OpenSSL does not read its last part as a port.
    std::string address;
  };

  // The host is a DNS name or an IP address; an IPv6 address may be in
  // brackets. Throws for anything else, before OpenSSL sees it: OpenSSL
  // parses the host as "host:port", and connects to the local host when no
  // host name is left (for "", ":5696", "[]" or "*") or when it cannot parse
  // the host at all (for "a:b:c" or "["). A NUL byte would cut the name
  // short. The port is a parameter of its own, so a host with a port is
  // refused too.
  static ServerHost parse_server_host(const std::string &host) {
    if (host.empty()) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE, "KMIP server host name must not be empty"
      );
    }
    // c_str() shows the host up to a NUL byte.
    const std::string shown =
        "KMIP server host '" + std::string(host.c_str()) + "'";
    if (host.find('\0') != std::string::npos) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE, shown + " contains a NUL byte"
      );
    }

    const bool bracketed =
        host.size() >= 2 && host.front() == '[' && host.back() == ']';
    const std::string name = bracketed ? host.substr(1, host.size() - 2) : host;
    // An IPv6 address has at least two colons; a2i_IPADDRESS() also takes
    // ":" alone, as "::".
    const bool ipv6 =
        std::count(name.begin(), name.end(), ':') >= 2 && is_ip_address(name);
    const bool valid =
        ipv6 || (!bracketed && name.find_first_of(":[]*") == std::string::npos);
    if (!valid) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          shown +
              " is not a host name or an IP address (an IPv6 address may be "
              "in brackets; the port is a separate parameter)"
      );
    }
    return {name, ipv6 ? "[" + name + "]" : name};
  }

  bool NetClientOpenSSL::connect() {
    const ServerHost server_host = parse_server_host(m_host);
    if (!m_isConnected) {
      bio_.reset();
      ctx_.reset();
    }

    std::unique_ptr<SSL_CTX, SslCtxDeleter> new_ctx(
        SSL_CTX_new(get_tls_client_method())
    );
    if (!new_ctx) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE, "SSL_CTX_new failed: " + getOpenSslError()
      );
    }

    configure_tls_verification(
        new_ctx.get(), nullptr, std::string{}, m_tls_verification
    );

    if (SSL_CTX_use_certificate_file(
            new_ctx.get(), m_clientCertificateFn.c_str(), SSL_FILETYPE_PEM
        ) != 1) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "Loading client certificate failed: " + m_clientCertificateFn + " (" +
              getOpenSslError() + ")"
      );
    }

    if (SSL_CTX_use_PrivateKey_file(
            new_ctx.get(), m_clientKeyFn.c_str(), SSL_FILETYPE_PEM
        ) != 1) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "Loading client key failed: " + m_clientKeyFn + " (" +
              getOpenSslError() + ")"
      );
    }

    if (SSL_CTX_check_private_key(new_ctx.get()) != 1) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "Client certificate/private key mismatch: " + getOpenSslError()
      );
    }

    if (SSL_CTX_load_verify_locations(
            new_ctx.get(), m_serverCaCertificateFn.c_str(), nullptr
        ) != 1) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "Loading server CA certificate failed: " + m_serverCaCertificateFn +
              " (" + getOpenSslError() + ")"
      );
    }

    std::unique_ptr<BIO, BioDeleter> new_bio(
        BIO_new_ssl_connect(new_ctx.get())
    );
    if (!new_bio) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "BIO_new_ssl_connect failed: " + getOpenSslError()
      );
    }

    SSL *ssl = nullptr;
    BIO_get_ssl(new_bio.get(), &ssl);
    if (!ssl) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE, "BIO_get_ssl failed: " + getOpenSslError()
      );
    }

    configure_tls_verification(
        new_ctx.get(), ssl, server_host.name, m_tls_verification
    );

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    if (BIO_set_conn_hostname(new_bio.get(), server_host.address.c_str()) !=
        1) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          "BIO_set_conn_hostname failed for '" + server_host.address +
              "': " + getOpenSslError()
      );
    }
    BIO_set_conn_port(new_bio.get(), m_port.c_str());

    if (m_timeout_ms > 0) {
      if (BIO_set_nbio(new_bio.get(), 1) != 1) {
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE, "BIO_set_nbio(1) failed before connect"
        );
      }

      const auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(m_timeout_ms);
      for (;;) {
        ERR_clear_error();
        const int connect_ret = BIO_do_connect(new_bio.get());
        if (connect_ret == 1) {
          break;
        }

        if (!BIO_should_retry(new_bio.get())) {
          throw KmipIOException(
              kmipcore::KMIP_IO_FAILURE,
              "BIO_do_connect failed: " + getOpenSslError()
          );
        }

        wait_for_bio_retry(
            new_bio.get(), deadline, "connect/handshake", m_timeout_ms
        );
      }

      restore_socket_blocking(new_bio.get());
      if (BIO_set_nbio(new_bio.get(), 0) != 1) {
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE, "BIO_set_nbio(0) failed after connect"
        );
      }
    } else {
      if (BIO_do_connect(new_bio.get()) != 1) {
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE,
            "BIO_do_connect failed: " + getOpenSslError()
        );
      }
    }

    ensure_tls_peer_verified(ssl, m_tls_verification);

    // Apply per-operation I/O timeouts on the now-connected socket so that
    // every subsequent BIO_read / BIO_write times out after m_timeout_ms ms.
    apply_socket_io_timeout(new_bio.get(), m_timeout_ms);

    bio_ = std::move(new_bio);
    ctx_ = std::move(new_ctx);

    m_isConnected = true;
    return true;
  }

  void NetClientOpenSSL::close() {
    m_isConnected = false;
    bio_.reset();
    ctx_.reset();
  }

  int NetClientOpenSSL::send(std::span<const std::uint8_t> data) {
    if (!checkConnected()) {
      return -1;
    }
    const int dlen = static_cast<int>(data.size());
    clear_socket_error();
    const int ret = BIO_write(bio_.get(), data.data(), dlen);
    if (ret <= 0 && BIO_should_retry(bio_.get()) &&
        is_timeout_socket_error(last_socket_error())) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE, timeoutMessage("send", m_timeout_ms)
      );
    }
    return ret;
  }

  int NetClientOpenSSL::recv(std::span<std::uint8_t> data) {
    if (!checkConnected()) {
      return -1;
    }
    const int dlen = static_cast<int>(data.size());
    clear_socket_error();
    const int ret = BIO_read(bio_.get(), data.data(), dlen);
    if (ret <= 0 && BIO_should_retry(bio_.get()) &&
        is_timeout_socket_error(last_socket_error())) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE, timeoutMessage("receive", m_timeout_ms)
      );
    }
    return ret;
  }

}  // namespace kmipclient
