/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// The few socket calls the test helpers make, for POSIX and Winsock.

#ifndef KMIPCLIENT_TESTS_TEST_SOCKETS_HPP
#define KMIPCLIENT_TESTS_TEST_SOCKETS_HPP

#ifdef _WIN32
  // Keep std::min and std::max usable in the tests.
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <cerrno>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <unistd.h>
#endif

#include <chrono>
#include <cstdint>
#include <string>
#include <system_error>
#include <utility>

namespace kmipclient::test {

#ifdef _WIN32
  using socket_t = SOCKET;
  inline constexpr socket_t no_socket = INVALID_SOCKET;

  /** Starts Winsock once for the test process; it is never cleaned up. */
  inline void init_sockets() {
    static const int result = [] {
      WSADATA data;
      return WSAStartup(MAKEWORD(2, 2), &data);
    }();
    if (result != 0) {
      throw std::system_error(result, std::system_category(), "WSAStartup");
    }
  }

  inline int socket_error() {
    return WSAGetLastError();
  }

  inline void close_socket(socket_t s) {
    ::closesocket(s);
  }

  /**
   * Makes a recv() blocked on @p s in another thread return, without
   * closing @p s (so that its handle cannot be reused meanwhile).
   * shutdown() alone does not wake it on Windows; CancelIoEx() cancels it.
   */
  inline void wake_socket(socket_t s) {
    ::shutdown(s, SD_BOTH);
    ::CancelIoEx(reinterpret_cast<HANDLE>(s), nullptr);
  }

  /** The call was interrupted and can be repeated. */
  inline bool is_interrupted(int err) {
    return err == WSAEINTR;
  }

  inline int poll_sockets(pollfd *fds, unsigned long n, int timeout_ms) {
    return ::WSAPoll(fds, n, timeout_ms);
  }

  inline bool set_blocking(socket_t s, bool blocking) {
    u_long non_blocking = blocking ? 0 : 1;
    return ::ioctlsocket(s, FIONBIO, &non_blocking) == 0;
  }

  /** Bounds each blocking recv() on @p s; 0 means no limit. */
  inline bool set_read_timeout(socket_t s, std::chrono::milliseconds timeout) {
    const DWORD ms = static_cast<DWORD>(timeout.count());
    return ::setsockopt(
               s,
               SOL_SOCKET,
               SO_RCVTIMEO,
               reinterpret_cast<const char *>(&ms),
               sizeof(ms)
           ) == 0;
  }

  /** accept() errors after which the server goes on: the client left. */
  inline bool is_transient_accept_error(int err) {
    return err == WSAEWOULDBLOCK || err == WSAECONNRESET || err == WSAEINTR;
  }
#else
  using socket_t = int;
  inline constexpr socket_t no_socket = -1;

  inline void init_sockets() {}

  inline int socket_error() {
    return errno;
  }

  inline void close_socket(socket_t s) {
    ::close(s);
  }

  /**
   * Makes a recv() blocked on @p s in another thread return, without
   * closing @p s (so that its descriptor cannot be reused meanwhile).
   */
  inline void wake_socket(socket_t s) {
    ::shutdown(s, SHUT_RDWR);
  }

  /** The call was interrupted and can be repeated. */
  inline bool is_interrupted(int err) {
    return err == EINTR;
  }

  inline int poll_sockets(pollfd *fds, unsigned long n, int timeout_ms) {
    return ::poll(fds, static_cast<nfds_t>(n), timeout_ms);
  }

  inline bool set_blocking(socket_t s, bool blocking) {
    const int flags = ::fcntl(s, F_GETFL);
    return flags >= 0 &&
           ::fcntl(
               s, F_SETFL, blocking ? flags & ~O_NONBLOCK : flags | O_NONBLOCK
           ) == 0;
  }

  /** Bounds each blocking recv() on @p s; 0 means no limit. */
  inline bool set_read_timeout(socket_t s, std::chrono::milliseconds timeout) {
    const timeval tv{
        static_cast<time_t>(timeout.count() / 1000),
        static_cast<suseconds_t>((timeout.count() % 1000) * 1000)
    };
    return ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
  }

  /** accept() errors after which the server goes on: the client left. */
  inline bool is_transient_accept_error(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == ECONNABORTED ||
           err == EINTR;
  }
#endif

  /** Text of a socket_error() value. */
  inline std::string socket_error_text(int err) {
    return std::system_category().message(err);
  }

  /** Owns a socket and closes it on destruction. */
  class Socket {
  public:
    explicit Socket(socket_t s = no_socket) : s_(s) {}
    ~Socket() {
      if (s_ != no_socket) {
        close_socket(s_);
      }
    }
    Socket(Socket &&other) noexcept : s_(std::exchange(other.s_, no_socket)) {}
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;

    [[nodiscard]] socket_t get() const { return s_; }
    [[nodiscard]] bool valid() const { return s_ != no_socket; }

  private:
    socket_t s_;
  };

  /** A TCP connection to 127.0.0.1:@p port; not valid() when it fails. */
  inline Socket tcp_connect(const std::string &port) {
    init_sockets();
    Socket s(::socket(AF_INET, SOCK_STREAM, 0));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<std::uint16_t>(std::stoi(port)));
    if (s.valid() &&
        ::connect(s.get(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) ==
            0) {
      return s;
    }
    return Socket();
  }

}  // namespace kmipclient::test

#endif  // KMIPCLIENT_TESTS_TEST_SOCKETS_HPP
