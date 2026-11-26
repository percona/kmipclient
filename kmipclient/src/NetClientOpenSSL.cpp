/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/NetClientOpenSSL.hpp"

#include "BioDeadline.hpp"
#include "kmipclient/KmipIOException.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstring>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <optional>
#include <sstream>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <poll.h>
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
#else
  static int last_socket_error() {
    return errno;
  }
  static std::string socket_error_string(int err) {
    return strerror(err);
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

  void detail::wait_for_bio_retry(
      BIO *bio,
      NetClient::Clock::time_point deadline,
      const char *op,
      int timeout_ms,
      bool exchange_deadline
  ) {
    int fd = -1;
    if (BIO_get_fd(bio, &fd) < 0 || fd < 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          std::string("Unable to obtain socket while waiting for ") + op
      );
    }

    const auto now = NetClient::Clock::now();
    if (now >= deadline) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          exchange_deadline ? std::string("KMIP ") + op +
                                  " timed out: exchange deadline passed"
                            : timeoutMessage(op, timeout_ms)
      );
    }
    // Rounded up, so that poll() does not return before the deadline, and
    // at most INT_MAX ms, which poll() takes as an int.
    const int wait_ms = static_cast<int>(std::min<long long>(
        std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count(),
        INT_MAX
    ));

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

#ifdef _WIN32
    const int poll_ret = WSAPoll(&pfd, 1, wait_ms);
#else
    const int poll_ret = poll(&pfd, 1, wait_ms);
    if (poll_ret < 0 && errno == EINTR) {
      return;  // the caller retries and waits for the rest
    }
#endif
    if (poll_ret < 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE,
          std::string("poll failed while waiting for ") + op + ": " +
              socket_error_string(last_socket_error())
      );
    }
    // Ready, or the wait ended (poll_ret == 0): the caller's retry either
    // makes progress or comes back here and finds the deadline passed.
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

  bool NetClientOpenSSL::connect() {
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

    configure_tls_verification(new_ctx.get(), ssl, m_host, m_tls_verification);

    if (m_timeout_ms <= 0) {
      // Blocking socket: let one BIO_read() skip non-application records.
      SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    } else {
      // OpenSSL 1.1.1 and later set this mode by default. Without it,
      // SSL_read() returns after each non-application record (such as a
      // NewSessionTicket or KeyUpdate), and the retry loop in send()/recv()
      // checks the deadline between records.
      SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);
    }
    BIO_set_conn_hostname(new_bio.get(), m_host.c_str());
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

        detail::wait_for_bio_retry(
            new_bio.get(), deadline, "connect/handshake", m_timeout_ms
        );
      }
      // The socket stays non-blocking: send() and recv() wait with poll()
      // against a deadline, as the handshake above does. A socket timeout
      // (SO_RCVTIMEO) would restart with every byte the peer sends.
    } else {
      if (BIO_do_connect(new_bio.get()) != 1) {
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE,
            "BIO_do_connect failed: " + getOpenSslError()
        );
      }
    }

    ensure_tls_peer_verified(ssl, m_tls_verification);

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
    return detail::io_with_deadline(
        bio_.get(), m_io_deadline, m_timeout_ms, "send", [&] {
          return BIO_write(bio_.get(), data.data(), dlen);
        }
    );
  }

  int NetClientOpenSSL::recv(std::span<std::uint8_t> data) {
    if (!checkConnected()) {
      return -1;
    }
    const int dlen = static_cast<int>(data.size());
    return detail::io_with_deadline(
        bio_.get(), m_io_deadline, m_timeout_ms, "receive", [&] {
          return BIO_read(bio_.get(), data.data(), dlen);
        }
    );
  }

}  // namespace kmipclient
