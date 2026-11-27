/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// After an exchange, no memory that OpenSSL holds or frees may still contain
// the decrypted response. The test replaces OpenSSL's allocator before
// OpenSSL allocates anything, which is why it is a program of its own.

#include "../src/IOUtils.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"

#include <gtest/gtest.h>
#include <openssl/ssl.h>

#if !defined(_WIN32) && defined(SSL_OP_CLEANSE_PLAINTEXT)

  #include "TlsTestServer.hpp"
  #include "kmipclient/KmipIOException.hpp"

  #include <algorithm>
  #include <array>
  #include <atomic>
  #include <cstdint>
  #include <cstdlib>
  #include <cstring>
  #include <mutex>
  #include <openssl/crypto.h>
  #include <string_view>
  #include <thread>
  #include <unordered_map>
  #include <vector>

namespace {

  // The response body is this pattern, repeated.
  constexpr std::string_view kMarker = "plaintext-marker-7e550a93";

  bool holds_marker(const void *p, size_t n) {
    const auto *b = static_cast<const char *>(p);
    return std::search(b, b + n, kMarker.begin(), kMarker.end()) != b + n;
  }

  // ---- OpenSSL allocator that tracks its live blocks ----
  //
  // Only the blocks that the test's own thread allocates are searched. The
  // TlsTestServer thread uses OpenSSL at the same time, and its blocks hold
  // the response it sends.

  struct Block {
    size_t size;
    std::thread::id owner;
  };

  // Never destroyed: OpenSSL frees memory at exit.
  auto &g_mutex = *new std::mutex;
  auto &g_live = *new std::unordered_map<void *, Block>;  // guarded by g_mutex
  const std::thread::id g_test_thread = std::this_thread::get_id();
  std::atomic<bool> g_scan_frees{false};
  std::atomic<int> g_freed_hits{0};

  // Zeroed, so that a block holds only what OpenSSL writes to it, not bytes
  // that an earlier exchange left on the heap.
  void *hook_malloc(size_t n, const char *, int) {
    void *p = std::calloc(1, n == 0 ? 1 : n);
    if (p != nullptr) {
      const std::lock_guard<std::mutex> lock(g_mutex);
      g_live[p] = {n, std::this_thread::get_id()};
    }
    return p;
  }

  void hook_free(void *p, const char *, int) {
    if (p == nullptr) {
      return;
    }
    Block block{0, {}};
    {
      const std::lock_guard<std::mutex> lock(g_mutex);
      const auto it = g_live.find(p);
      if (it != g_live.end()) {
        block = it->second;
        g_live.erase(it);
      }
    }
    if (g_scan_frees && block.owner == g_test_thread &&
        holds_marker(p, block.size)) {
      ++g_freed_hits;
    }
    std::free(p);
  }

  // Always moves the block, so the old one goes through the free scan.
  void *hook_realloc(void *p, size_t n, const char *file, int line) {
    void *fresh = hook_malloc(n, file, line);
    if (fresh != nullptr && p != nullptr) {
      size_t old_size = 0;
      {
        const std::lock_guard<std::mutex> lock(g_mutex);
        old_size = g_live.at(p).size;
      }
      std::memcpy(fresh, p, std::min(old_size, n));
      hook_free(p, file, line);
    }
    return fresh;
  }

  int live_blocks_holding_marker() {
    const std::lock_guard<std::mutex> lock(g_mutex);
    int hits = 0;
    for (const auto &[p, block] : g_live) {
      if (block.owner == g_test_thread && holds_marker(p, block.size)) {
        ++hits;
      }
    }
    return hits;
  }

  // Runs before main(), before OpenSSL allocates anything in this program.
  const bool g_hooked =
      CRYPTO_set_mem_functions(hook_malloc, hook_realloc, hook_free) == 1;

  // A TTLV-framed message: 8-byte header, then body_size bytes of fill.
  std::vector<uint8_t> message(uint32_t body_size, bool marker) {
    std::vector<uint8_t> msg{0x42, 0x00, 0x7B, 0x01};
    for (int shift = 24; shift >= 0; shift -= 8) {
      msg.push_back(static_cast<uint8_t>(body_size >> shift));
    }
    for (uint32_t i = 0; i < body_size; ++i) {
      msg.push_back(
          static_cast<uint8_t>(marker ? kMarker[i % kMarker.size()] : 0x11)
      );
    }
    return msg;
  }

  // How much of the response the client reads before it closes.
  enum class Read {
    Whole,       // IOUtils::do_exchange()
    HeaderOnly,  // only the 8-byte header; the body stays unread
    OverLimit,   // do_exchange() refuses the length and closes
  };

  struct Case {
    const char *name;
    uint32_t body_size;
    Read read;
  };

}  // namespace

TEST(TlsPlaintextTest, DecryptedResponseIsZeroed) {
  ASSERT_TRUE(g_hooked) << "OpenSSL allocated memory before the hook";
  using namespace kmipclient::test;

  const Case cases[] = {
      {"one record", 64, Read::Whole},
      // TLS records hold at most 16 KiB.
      {"several records", 40000, Read::Whole},
      {"record left unread", 64, Read::HeaderOnly},
      {"record over the size limit", 64, Read::OverLimit},
  };
  for (const Case &c : cases) {
    SCOPED_TRACE(c.name);
    const auto request = message(48, false);
    const auto response = message(c.body_size, true);

    TempDir dir;
    TestCert cert(dir, "server", "IP:127.0.0.1");
    TlsTestServer server(cert, [&](SSL *ssl) {
      std::vector<uint8_t> in(request.size());
      size_t got = 0;
      if (SSL_read_ex(ssl, in.data(), in.size(), &got) != 1) {
        return;
      }
      SSL_write(ssl, response.data(), static_cast<int>(response.size()));
      uint8_t byte = 0;
      while (SSL_read(ssl, &byte, 1) > 0) {  // wait until the client closes
      }
    });

    kmipclient::NetClientOpenSSL client(
        "127.0.0.1", server.port(), cert.cert(), cert.key(), cert.cert(), 5000
    );
    client.connect();
    g_freed_hits = 0;

    switch (c.read) {
      case Read::Whole: {
        kmipclient::IOUtils io(client);
        kmipcore::secure_bytes received;
        io.do_exchange(request, received, 1024 * 1024);
        ASSERT_TRUE(std::ranges::equal(received, response))
            << "the response did not arrive as sent";
        EXPECT_EQ(live_blocks_holding_marker(), 0)
            << "memory OpenSSL holds still has the decrypted response";
        break;
      }
      case Read::HeaderOnly: {
        ASSERT_EQ(client.send(request), static_cast<int>(request.size()));
        std::array<uint8_t, 8> header{};
        ASSERT_EQ(client.recv(header), static_cast<int>(header.size()));
        // OpenSSL has decrypted the whole record; the body is not read yet.
        EXPECT_GT(live_blocks_holding_marker(), 0)
            << "the scan does not see the unread response";
        break;
      }
      case Read::OverLimit: {
        kmipclient::IOUtils io(client);
        kmipcore::secure_bytes received;
        g_scan_frees = true;
        EXPECT_THROW(
            io.do_exchange(request, received, 16), kmipclient::KmipIOException
        );
        g_scan_frees = false;
        break;
      }
    }

    g_scan_frees = true;
    client.close();
    g_scan_frees = false;
    EXPECT_EQ(g_freed_hits.load(), 0)
        << "memory OpenSSL freed still had the decrypted response";

    EXPECT_TRUE(server.wait_for_completed(1));
    server.stop();
    EXPECT_EQ(server.error(), "");
  }
}

#elif defined(_WIN32)

TEST(TlsPlaintextTest, NotOnWindows) {
  GTEST_SKIP() << "uses POSIX sockets for the test server";
}

#else

TEST(TlsPlaintextTest, NeedsOpenSsl3) {
  GTEST_SKIP() << "this OpenSSL has no SSL_OP_CLEANSE_PLAINTEXT";
}

#endif
