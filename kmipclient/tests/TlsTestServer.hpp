/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// Test helpers: certificates written to a temporary directory, and an
// in-process TLS server on 127.0.0.1 that hands each accepted, handshaken
// connection to a callback. For POSIX and Windows.

#ifndef KMIPCLIENT_TESTS_TLS_TEST_SERVER_HPP
#define KMIPCLIENT_TESTS_TLS_TEST_SERVER_HPP

#include "TempDir.hpp"
#include "TestSockets.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <exception>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#ifdef _WIN32
  #include <fcntl.h>
  #include <io.h>
  #include <sys/stat.h>
#else
  #include <csignal>
  #include <fcntl.h>
  #include <unistd.h>
#endif

namespace kmipclient::test {

  /**
   * An EC P-256 certificate and its private key, as PEM files (with mode
   * 0600 on POSIX).
   *
   * EC P-256 is available in every OpenSSL the library builds with and is
   * allowed by FIPS providers. The certificate is valid for one hour, has a
   * serial number unique within the test process, and passes verification
   * with X509_V_FLAG_X509_STRICT.
   */
  class TestCert {
  public:
    /**
     * @param dir directory for the PEM files.
     * @param name file name stem; it must be unique within @p dir (the
     *        files are created exclusively, so a second certificate with the
     *        same name throws).
     * @param subject_alt_name e.g. "IP:127.0.0.1" or "DNS:other.example".
     * @param issuer without it, the certificate is self-signed, is a CA, and
     *        is also the CA file that trusts it. With it, the certificate is a
     *        leaf signed by @p issuer, and issuer->cert() is the CA file.
     */
    TestCert(
        const TempDir &dir,
        const std::string &name,
        const std::string &subject_alt_name,
        const TestCert *issuer = nullptr
    )
      : cert_path_(dir.path() / (name + ".pem")),
        key_path_(dir.path() / (name + ".key")),
        pkey_(generate_key(), EVP_PKEY_free),
        x509_(X509_new(), X509_free) {
      X509 *x = x509_.get();
      check(x != nullptr && X509_set_version(x, 2) == 1, "X509_set_version");
      check(
          ASN1_INTEGER_set(X509_get_serialNumber(x), next_serial()) == 1,
          "serial number"
      );
      check(
          X509_gmtime_adj(X509_getm_notBefore(x), -60) != nullptr &&
              X509_gmtime_adj(X509_getm_notAfter(x), 3600) != nullptr,
          "validity"
      );
      check(X509_set_pubkey(x, pkey_.get()) == 1, "X509_set_pubkey");
      // Built separately: OpenSSL 4 returns a const subject name.
      std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> subject(
          X509_NAME_new(), X509_NAME_free
      );
      check(
          subject &&
              X509_NAME_add_entry_by_txt(
                  subject.get(),
                  "CN",
                  MBSTRING_ASC,
                  reinterpret_cast<const unsigned char *>(name.c_str()),
                  -1,
                  -1,
                  0
              ) == 1 &&
              X509_set_subject_name(x, subject.get()) == 1,
          "subject name"
      );

      // Self-signed unless an issuer is given.
      X509 *signer_cert = x;
      EVP_PKEY *signer_key = pkey_.get();
      if (issuer != nullptr) {
        signer_cert = issuer->x509_.get();
        signer_key = issuer->pkey_.get();
      }
      const bool is_ca = issuer == nullptr;
      check(
          X509_set_issuer_name(x, X509_get_subject_name(signer_cert)) == 1,
          "issuer name"
      );
      add_extension(x, signer_cert, NID_subject_alt_name, subject_alt_name);
      add_extension(
          x,
          signer_cert,
          NID_basic_constraints,
          is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE"
      );
      // A self-signed certificate is also used as a server certificate, so
      // it needs digitalSignature as well.
      add_extension(
          x,
          signer_cert,
          NID_key_usage,
          is_ca ? "critical,digitalSignature,keyCertSign,cRLSign"
                : "critical,digitalSignature"
      );
      // The subject key identifier first: a self-signed certificate's
      // authority key identifier is taken from it.
      add_extension(x, signer_cert, NID_subject_key_identifier, "hash");
      add_extension(
          x, signer_cert, NID_authority_key_identifier, "keyid:always"
      );
      check(X509_sign(x, signer_key, EVP_sha256()) > 0, "X509_sign");

      write_pem(cert_path_, [&](BIO *b) { return PEM_write_bio_X509(b, x); });
      write_pem(key_path_, [&](BIO *b) {
        return PEM_write_bio_PrivateKey(
            b, pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr
        );
      });
    }

    TestCert(const TestCert &) = delete;
    TestCert &operator=(const TestCert &) = delete;

    [[nodiscard]] std::string cert() const { return cert_path_.string(); }
    [[nodiscard]] std::string key() const { return key_path_.string(); }

  private:
    static void check(bool ok, const std::string &what) {
      if (!ok) {
        throw std::runtime_error("test certificate: " + what);
      }
    }

    static long next_serial() {
      static std::atomic<long> serial{1};
      return serial++;
    }

    static EVP_PKEY *generate_key() {
      std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
          EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free
      );
      EVP_PKEY *key = nullptr;
      check(
          ctx && EVP_PKEY_keygen_init(ctx.get()) == 1 &&
              EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                  ctx.get(), NID_X9_62_prime256v1
              ) == 1 &&
              EVP_PKEY_keygen(ctx.get(), &key) == 1,
          "key generation"
      );
      return key;
    }

    static void add_extension(
        X509 *x509, X509 *issuer, int nid, const std::string &value
    ) {
      X509V3_CTX ctx{};
      X509V3_set_ctx_nodb(&ctx);
      X509V3_set_ctx(&ctx, issuer, x509, nullptr, nullptr, 0);
      X509_EXTENSION *ext = X509V3_EXT_conf_nid(
          nullptr, &ctx, nid, const_cast<char *>(value.c_str())
      );
      const bool ok = ext != nullptr && X509_add_ext(x509, ext, -1) == 1;
      X509_EXTENSION_free(ext);
      check(ok, std::string("extension ") + OBJ_nid2sn(nid));
    }

    // Encodes into a memory BIO, then creates the file exclusively (with
    // mode 0600 and without following a symbolic link on POSIX) and checks
    // every step, close() included. No FILE * goes to OpenSSL: on Windows
    // its DLL may use another C runtime.
    template<typename Write>
    static void write_pem(const std::filesystem::path &path, Write &&write) {
      std::unique_ptr<BIO, decltype(&BIO_free)> bio(
          BIO_new(BIO_s_mem()), BIO_free
      );
      check(bio && write(bio.get()) == 1, "PEM encoding " + path.string());
      char *data = nullptr;
      const long size = BIO_get_mem_data(bio.get(), &data);
      check(size > 0 && data != nullptr, "PEM encoding " + path.string());
#ifdef _WIN32
      const int fd = ::_wopen(
          path.c_str(),
          _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT,
          _S_IREAD | _S_IWRITE
      );
#else
      const int fd = ::open(
          path.c_str(),
          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
          0600
      );
#endif
      check(fd >= 0, "cannot create " + path.string());
      bool written = true;
      for (long done = 0; written && done < size;) {
#ifdef _WIN32
        const long n =
            ::_write(fd, data + done, static_cast<unsigned>(size - done));
#else
        const long n =
            static_cast<long>(::write(fd, data + done, size_t(size - done)));
#endif
        if (n < 0 && errno == EINTR) {
          continue;
        }
        written = n > 0;
        if (written) {
          done += n;
        }
      }
#ifdef _WIN32
      const bool closed = ::_close(fd) == 0;
#else
      const bool closed = ::close(fd) == 0;
#endif
      check(written && closed, "cannot write " + path.string());
    }

    std::filesystem::path cert_path_;
    std::filesystem::path key_path_;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_;
    std::unique_ptr<X509, decltype(&X509_free)> x509_;
  };

#ifndef _WIN32
  /**
   * Ignores SIGPIPE in the whole process while any instance exists, and
   * restores the previous disposition when the last one is destroyed.
   *
   * A write to a peer that went away raises SIGPIPE in the thread that
   * wrote: on the server thread, and on the test's own thread when its
   * client sends a TLS close_notify to a server that has closed the
   * connection (macOS reports that at once).
   *
   * The disposition saved by the first instance is restored as it was, so a
   * change other code makes to SIGPIPE while a server exists is lost.
   */
  class IgnoreSigpipe {
  public:
    IgnoreSigpipe() {
      const std::lock_guard<std::mutex> lock(mutex());
      if (users() == 0) {
        struct sigaction ignore{};
        ignore.sa_handler = SIG_IGN;
        sigemptyset(&ignore.sa_mask);
        if (sigaction(SIGPIPE, &ignore, &previous()) != 0) {
          throw std::system_error(
              errno, std::generic_category(), "sigaction(SIGPIPE)"
          );
        }
      }
      ++users();
    }
    ~IgnoreSigpipe() {
      const std::lock_guard<std::mutex> lock(mutex());
      if (--users() == 0) {
        (void) sigaction(SIGPIPE, &previous(), nullptr);  // cannot report
      }
    }
    IgnoreSigpipe(const IgnoreSigpipe &) = delete;
    IgnoreSigpipe &operator=(const IgnoreSigpipe &) = delete;

  private:
    static std::mutex &mutex() {
      static std::mutex m;
      return m;
    }
    static int &users() {
      static int n = 0;
      return n;
    }
    static struct sigaction &previous() {
      static struct sigaction action{};
      return action;
    }
  };
#endif

  /**
   * TLS server on 127.0.0.1 and a free port.
   *
   * Connections are served one at a time on a server thread: each is
   * handshaken with @p cert and passed to @p on_connection (which may be
   * empty: the connection is closed right after the handshake). After the
   * handler returns, the server sends a TLS close_notify (unless the
   * connection failed with a fatal TLS error) and closes the connection.
   * The client reliably reads the close_notify only if the handler read
   * everything the client sent: closing a socket with unread data resets
   * the connection. The server does not ask for a client certificate.
   *
   * - Anything the handler captures by reference must outlive the server:
   *   declare it before the server, or call stop() first.
   * - An exception thrown by the handler is kept; error() returns its text.
   * - stop() (also run by the destructor) shuts down the connection being
   *   served and closes the listening socket: a handler blocked in
   *   SSL_read() returns at once, and later connects are refused. A handler
   *   must return once SSL_read() or SSL_write() fails.
   * - read_timeout bounds each read of a stalled client; 0 means no limit.
   * - On POSIX, SIGPIPE is ignored in the process while a server exists
   *   (see IgnoreSigpipe), so neither the server nor a client of it ends
   *   the test by writing to a peer that went away. Declare the client
   *   after the server, so that the client is closed first.
   */
  class TlsTestServer {
  public:
    using Handler = std::function<void(SSL *)>;

    explicit TlsTestServer(
        const TestCert &cert,
        Handler on_connection = {},
        std::chrono::milliseconds read_timeout = std::chrono::seconds(5)
    )
      : on_connection_(std::move(on_connection)), read_timeout_(read_timeout) {
      ctx_.reset(SSL_CTX_new(TLS_server_method()));
      if (!ctx_ ||
          SSL_CTX_use_certificate_file(
              ctx_.get(), cert.cert().c_str(), SSL_FILETYPE_PEM
          ) != 1 ||
          SSL_CTX_use_PrivateKey_file(
              ctx_.get(), cert.key().c_str(), SSL_FILETYPE_PEM
          ) != 1 ||
          SSL_CTX_check_private_key(ctx_.get()) != 1) {
        throw std::runtime_error("server SSL_CTX setup failed");
      }

      // Non-blocking, so that accept() cannot block when the connection
      // that poll() reported is gone by the time it runs.
      init_sockets();
      listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      socklen_t addr_len = sizeof(addr);
      if (listen_fd_ == no_socket || !set_blocking(listen_fd_, false) ||
          ::bind(
              listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)
          ) != 0 ||
          ::listen(listen_fd_, 8) != 0 ||
          ::getsockname(
              listen_fd_, reinterpret_cast<sockaddr *>(&addr), &addr_len
          ) != 0) {
        close_listener();
        throw std::runtime_error("server socket setup failed");
      }
      port_ = ntohs(addr.sin_port);
      try {
        thread_ = std::thread([this] { serve(); });
      } catch (...) {
        // The destructor does not run for a constructor that throws.
        close_listener();
        throw;
      }
    }

    ~TlsTestServer() { stop(); }

    TlsTestServer(const TlsTestServer &) = delete;
    TlsTestServer &operator=(const TlsTestServer &) = delete;

    /**
     * Stops serving and waits for the server thread. Calling it again does
     * nothing; call it from one thread at a time, and never from a handler
     * (it would wait for its own thread).
     */
    void stop() {
      {
        // Under the lock the socket cannot be closed (and its handle
        // reused) between reading and waking it; serve() closes it.
        const std::lock_guard<std::mutex> lock(fd_mutex_);
        stop_ = true;
        if (active_fd_ != no_socket) {
          wake_socket(active_fd_);
        }
      }
      if (thread_.joinable()) {
        thread_.join();
      }
      close_listener();
    }

    [[nodiscard]] std::string port() const { return std::to_string(port_); }

    /** Connections whose TLS handshake completed on the server side. */
    [[nodiscard]] int handshakes() const { return handshakes_.load(); }

    /** Connections whose handler returned (or threw). */
    [[nodiscard]] int completed() const { return completed_.load(); }

    /**
     * Waits up to @p timeout until @p n handshakes completed: with TLS 1.3
     * the client is done before the server's SSL_accept() returns.
     */
    [[nodiscard]] bool wait_for_handshakes(
        int n, std::chrono::milliseconds timeout = std::chrono::seconds(5)
    ) const {
      return wait_for(handshakes_, n, timeout);
    }

    /** Waits up to @p timeout until @p n handlers returned. */
    [[nodiscard]] bool wait_for_completed(
        int n, std::chrono::milliseconds timeout = std::chrono::seconds(5)
    ) const {
      return wait_for(completed_, n, timeout);
    }

    /**
     * Text of the first error: an exception a handler threw (its what(), or
     * a fixed text when that is empty or it is not a std::exception), or a
     * failed socket call on the server thread. "" if there was none.
     */
    [[nodiscard]] std::string error() const {
      const std::lock_guard<std::mutex> lock(error_mutex_);
      return error_;
    }

  private:
    static bool wait_for(
        const std::atomic<int> &counter,
        int n,
        std::chrono::milliseconds timeout
    ) {
      const auto until = std::chrono::steady_clock::now() + timeout;
      while (counter.load() < n) {
        if (std::chrono::steady_clock::now() >= until) {
          return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
      return true;
    }

    void serve() {
      while (!stop_) {
        pollfd pfd{listen_fd_, POLLIN, 0};
        const int ready = poll_sockets(&pfd, 1, 50);
        if (ready < 0 && !is_interrupted(socket_error())) {
          record_socket_error("poll");  // would fail again at once
          break;
        }
        if (ready <= 0) {
          continue;
        }
        const socket_t fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd == no_socket) {
          if (is_transient_accept_error(socket_error())) {
            continue;
          }
          // Such as EMFILE: the connection stays pending, and accept()
          // would fail again at once.
          record_socket_error("accept");
          break;
        }
        {
          const std::lock_guard<std::mutex> lock(fd_mutex_);
          if (stop_) {  // stop() ran after poll(): do not serve this one
            close_socket(fd);
            break;
          }
          active_fd_ = fd;
        }
        if (prepare(fd)) {
          serve_connection(fd);
        }
        const std::lock_guard<std::mutex> lock(fd_mutex_);
        active_fd_ = no_socket;
        close_socket(fd);
      }
    }

    // Makes the accepted socket blocking (BSD, macOS and Windows pass the
    // non-blocking mode on from the listener) and bounds each read, so that
    // a client that stops sending cannot hang the server thread.
    // An error after stop() woke the socket is not reported.
    bool prepare(socket_t fd) {
      if (!set_blocking(fd, true)) {
        if (!stop_) {
          record_socket_error("set_blocking");
        }
        return false;
      }
      if (!set_read_timeout(fd, read_timeout_)) {
        if (!stop_) {
          record_socket_error("setsockopt(SO_RCVTIMEO)");
        }
        return false;
      }
      return true;
    }

    void serve_connection(socket_t fd) {
      SSL *ssl = SSL_new(ctx_.get());
      // OpenSSL takes a Windows SOCKET as an int.
      if (ssl != nullptr && SSL_set_fd(ssl, static_cast<int>(fd)) == 1 &&
          SSL_accept(ssl) == 1) {
        ++handshakes_;
        if (on_connection_) {
          try {
            on_connection_(ssl);
          } catch (const std::exception &e) {
            record_error(
                *e.what() != '\0' ? e.what() : "exception with an empty message"
            );
          } catch (...) {
            record_error("unknown exception");
          }
        }
        ++completed_;
        // Not after a fatal TLS error, which leaves the connection in the
        // init state; OpenSSL does not allow SSL_shutdown() then.
        if (!SSL_in_init(ssl)) {
          SSL_shutdown(ssl);
        }
      }
      // Nothing from this connection is left for the next one.
      ERR_clear_error();
      SSL_free(ssl);
    }

    void record_socket_error(const char *call) {
      record_error(
          std::string(call) + ": " + socket_error_text(socket_error())
      );
    }

    void record_error(const std::string &what) {
      const std::lock_guard<std::mutex> lock(error_mutex_);
      if (error_.empty()) {
        error_ = what;
      }
    }

    void close_listener() {
      if (listen_fd_ != no_socket) {
        close_socket(listen_fd_);
        listen_fd_ = no_socket;
      }
    }

    struct CtxDeleter {
      void operator()(SSL_CTX *c) const { SSL_CTX_free(c); }
    };

#ifndef _WIN32
    IgnoreSigpipe ignore_sigpipe_;  // first: it outlives the server thread
#endif
    Handler on_connection_;
    std::chrono::milliseconds read_timeout_;
    std::unique_ptr<SSL_CTX, CtxDeleter> ctx_;
    socket_t listen_fd_ = no_socket;
    unsigned short port_ = 0;
    std::atomic<bool> stop_{false};
    std::mutex fd_mutex_;
    socket_t active_fd_ = no_socket;  // guarded by fd_mutex_
    std::atomic<int> handshakes_{0};
    std::atomic<int> completed_{0};
    mutable std::mutex error_mutex_;
    std::string error_;  // guarded by error_mutex_
    std::thread thread_;
  };

}  // namespace kmipclient::test

#endif  // KMIPCLIENT_TESTS_TLS_TEST_SERVER_HPP
