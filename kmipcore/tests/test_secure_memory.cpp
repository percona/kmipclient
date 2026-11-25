/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/key_parser.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_formatter.hpp"
#include "kmipcore/kmip_protocol.hpp"
#include "kmipcore/kmip_requests.hpp"
#include "kmipcore/response_parser.hpp"
#include "kmipcore/secure_memory.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

using namespace kmipcore;

#define EXPECT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      throw std::runtime_error(                                                \
          std::string(__FILE__) + ":" + std::to_string(__LINE__) +             \
          ": expectation failed: " #cond                                       \
      );                                                                       \
    }                                                                          \
  } while (false)

// ---- Inspecting blocks as they are freed ----
//
// secure_allocator::deallocate() must zero a block before it hands it back to
// the runtime. Reading the block after it is freed would be undefined, so the
// global allocation functions are replaced and operator delete inspects the
// watched block just before releasing it.

namespace {
  const void *g_watch_ptr = nullptr;
  std::size_t g_watch_len = 0;
  bool g_watch_freed = false;
  bool g_watch_zeroed = false;

  void inspect_before_free(void *p) noexcept {
    if (p == nullptr || p != g_watch_ptr) {
      return;
    }
    const auto *bytes = static_cast<const unsigned char *>(p);
    bool zeroed = true;
    for (std::size_t i = 0; i < g_watch_len; ++i) {
      if (bytes[i] != 0) {
        zeroed = false;
        break;
      }
    }
    g_watch_freed = true;
    g_watch_zeroed = zeroed;
    g_watch_ptr = nullptr;
  }

  // Watches the first @p len bytes of the block at @p p.
  void watch_block(const void *p, std::size_t len) {
    g_watch_ptr = p;
    g_watch_len = len;
    g_watch_freed = false;
    g_watch_zeroed = false;
  }

  // While a scan is active, every block freed through operator delete is
  // searched for the secret; a hit is a copy of the secret that was released
  // without being zeroed.
  std::span<const unsigned char> g_scan_secret;
  std::size_t g_scan_hits = 0;

  void scan_before_free(const void *p, std::size_t len) noexcept {
    if (g_scan_secret.empty() || len < g_scan_secret.size()) {
      return;
    }
    const auto *bytes = static_cast<const unsigned char *>(p);
    if (std::search(
            bytes, bytes + len, g_scan_secret.begin(), g_scan_secret.end()
        ) != bytes + len) {
      ++g_scan_hits;
    }
  }

  // operator new stores the block size in front of the block so that
  // operator delete can scan the whole block, also for unsized deletes. The
  // header keeps the alignment operator new guarantees, which on some
  // platforms (macOS arm64, Windows x64) is larger than max_align_t's.
  constexpr std::size_t kBlockHeader = std::max<std::size_t>(
      {alignof(std::max_align_t), __STDCPP_DEFAULT_NEW_ALIGNMENT__}
  );

  // Filled with a pattern, so the scan never reads bytes no one wrote.
  constexpr unsigned char kFreshBlockByte = 0xA5;

  void *allocate_block(std::size_t n) {
    if (n > SIZE_MAX - kBlockHeader) {
      throw std::bad_alloc();
    }
    auto *raw = static_cast<unsigned char *>(std::malloc(kBlockHeader + n));
    if (raw == nullptr) {
      throw std::bad_alloc();
    }
    *reinterpret_cast<std::size_t *>(raw) = n;
    std::memset(raw + kBlockHeader, kFreshBlockByte, n);
    return raw + kBlockHeader;
  }

  void free_block(void *p) noexcept {
    if (p == nullptr) {
      return;
    }
    auto *raw = static_cast<unsigned char *>(p) - kBlockHeader;
    scan_before_free(p, *reinterpret_cast<const std::size_t *>(raw));
    inspect_before_free(p);
    std::free(raw);
  }
}  // namespace

void *operator new(std::size_t n) {
  return allocate_block(n);
}

void operator delete(void *p) noexcept {
  free_block(p);
}

void operator delete(void *p, std::size_t /*n*/) noexcept {
  free_block(p);
}

void testSecureClearZeroes() {
  unsigned char buf[16];
  for (unsigned char &b : buf) {
    b = 0xAB;
  }
  secure_clear(buf, sizeof(buf));
  for (unsigned char b : buf) {
    EXPECT(b == 0);
  }

  // No-ops must not crash.
  secure_clear(nullptr, 16);
  secure_clear(buf, 0);

  std::cout << "testSecureClearZeroes passed" << std::endl;
}

void testHeterogeneousByteCompare() {
  const std::vector<unsigned char> plain{0x01, 0x02, 0x03};
  secure_bytes secure{0x01, 0x02, 0x03};

  EXPECT(secure == plain);
  EXPECT(plain == secure);
  EXPECT(!(secure != plain));

  secure.push_back(0x04);
  EXPECT(secure != plain);
  EXPECT(plain != secure);

  std::cout << "testHeterogeneousByteCompare passed" << std::endl;
}

void testHeterogeneousStringCompare() {
  const std::string plain = "s3cr3t";
  secure_string secure = "s3cr3t";

  EXPECT(secure == plain);
  EXPECT(plain == secure);
  EXPECT(secure != std::string("other"));
  EXPECT(std::string("other") != secure);
  EXPECT(secure == "s3cr3t");
  EXPECT("s3cr3t" == secure);
  EXPECT(secure != "other");
  EXPECT("other" != secure);
  EXPECT(!(secure != "s3cr3t"));
  EXPECT(!("s3cr3t" != secure));

  std::cout << "testHeterogeneousStringCompare passed" << std::endl;
}

void testSecureStringHashAndBaseCopy() {
  // An embedded NUL: the hash covers the whole value, like string_view's.
  const std::string_view value("ab\0cd", 5);
  const secure_string s(value);
  EXPECT(s.size() == 5);
  EXPECT(std::hash<secure_string>{}(s) == std::hash<std::string_view>{}(value));

  std::unordered_set<secure_string> set;
  set.insert(s);
  set.insert(secure_string("other"));
  EXPECT(set.size() == 2);
  EXPECT(set.count(secure_string(value)) == 1);
  EXPECT(set.count(secure_string("ab")) == 0);

  // Copy from the base string, which is left as it was.
  const secure_string::base_type base("copied value");
  const secure_string copy(base);
  EXPECT(copy == "copied value");
  EXPECT(base == "copied value");

  std::cout << "testSecureStringHashAndBaseCopy passed" << std::endl;
}

// Reads bytes past a container's size(), in its retained capacity. ASan
// container annotations (libc++) report such reads, so they are exempt here.
#if defined(_MSC_VER) && !defined(__clang__)
  #define KMIP_NO_SANITIZE_ADDRESS __declspec(no_sanitize_address)
#else
  #define KMIP_NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))
#endif
KMIP_NO_SANITIZE_ADDRESS bool all_zero_past_size(const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (p[i] != 0) {
      return false;
    }
  }
  return true;
}

// F12: release() must scrub the bytes left behind in the retained capacity.
void testReleaseScrubsRetainedCapacity() {
  SerializationBuffer buf(64);

  const std::vector<uint8_t> secret{0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22};
  buf.writeBytes(std::as_bytes(std::span{secret}));
  EXPECT(buf.size() == secret.size());

  // Capture the storage pointer before release(); clear() keeps capacity, so
  // the pointer stays valid and no reallocation happens.
  const uint8_t *storage = buf.data();
  const size_t written = buf.size();

  const secure_bytes released = buf.release();

  // The returned copy still holds the serialized secret ...
  EXPECT(released.size() == written);
  EXPECT(released[0] == 0xDE);

  // ... but the buffer's retained capacity has been zeroed.
  EXPECT(buf.size() == 0);
  EXPECT(all_zero_past_size(storage, written));

  std::cout << "testReleaseScrubsRetainedCapacity passed" << std::endl;
}

void testShrinkReleasesCapacity() {
  SerializationBuffer buf(64);
  const std::vector<uint8_t> secret{0x01, 0x02, 0x03, 0x04};
  buf.writeBytes(std::as_bytes(std::span{secret}));
  EXPECT(buf.capacity() > 0);

  buf.shrink();
  EXPECT(buf.size() == 0);
  EXPECT(buf.capacity() == 0);

  std::cout << "testShrinkReleasesCapacity passed" << std::endl;
}

void testSecureBytesScrubbedOnDestruction() {
  const unsigned char *storage = nullptr;
  std::size_t len = 0;
  {
    secure_bytes secret(64, 0xAB);
    storage = secret.data();
    len = secret.size();
    watch_block(storage, len);
  }
  EXPECT(g_watch_freed);
  EXPECT(g_watch_zeroed);

  std::cout << "testSecureBytesScrubbedOnDestruction passed" << std::endl;
}

void testSecureBytesScrubbedOnReallocation() {
  secure_bytes secret(16, 0xCD);
  const unsigned char *old_block = secret.data();
  watch_block(old_block, secret.size());

  // Growing past the capacity moves the bytes to a new block and frees the
  // old one, which must be zeroed first. reserve() may round the capacity
  // up, so grow until the storage actually moves.
  while (secret.data() == old_block) {
    secret.push_back(0xEF);
  }
  EXPECT(g_watch_freed);
  EXPECT(g_watch_zeroed);
  EXPECT(secret.size() > 16);
  EXPECT(secret[0] == 0xCD && secret[15] == 0xCD && secret[16] == 0xEF);

  std::cout << "testSecureBytesScrubbedOnReallocation passed" << std::endl;
}

void testSecureStringScrubbedOnDestruction() {
  {
    // Long enough to be heap-allocated rather than kept in the small-string
    // buffer.
    secure_string secret(128, 'x');
    watch_block(secret.data(), secret.size());
  }
  EXPECT(g_watch_freed);
  EXPECT(g_watch_zeroed);

  std::cout << "testSecureStringScrubbedOnDestruction passed" << std::endl;
}

// ---- secure_string and its inline (small-string) buffer ----
//
// Short values live inside the string object. The strings below are built
// in a buffer owned by the test, so their storage can be read after they
// are destroyed or moved from.

namespace {
  constexpr const char *kShortSecret = "hunter2!Qz7#";  // fits inline

  using StringStorage =
      std::array<unsigned char, sizeof(secure_string)>;  // NOLINT

  // True when any 4 consecutive bytes of `text` are in `storage`: a move or
  // the string's own bookkeeping may overwrite part of a copy, so searching
  // for the whole value would miss what is left.
  bool storage_holds(const StringStorage &storage, std::string_view text) {
    const std::string_view bytes(
        reinterpret_cast<const char *>(storage.data()), storage.size()
    );
    for (std::size_t i = 0; i + 4 <= text.size(); ++i) {
      if (bytes.find(text.substr(i, 4)) != std::string_view::npos) {
        return true;
      }
    }
    return false;
  }
}  // namespace

void testSecureStringShortValueIsWipedOnDestruction() {
  alignas(secure_string) StringStorage storage{};
  auto *s = new (storage.data()) secure_string(kShortSecret);
  EXPECT(storage_holds(storage, kShortSecret));  // it is inline
  s->~secure_string();
  EXPECT(!storage_holds(storage, kShortSecret));

  std::cout << "testSecureStringShortValueIsWipedOnDestruction passed"
            << std::endl;
}

void testSecureStringGrownFromShortIsWiped() {
  // Growing past the inline buffer moves the value to the heap; what is
  // left of the old inline copy must not survive the string.
  alignas(secure_string) StringStorage storage{};
  auto *s = new (storage.data()) secure_string(kShortSecret);
  s->append(100, 'x');
  s->~secure_string();
  EXPECT(!storage_holds(storage, kShortSecret));

  std::cout << "testSecureStringGrownFromShortIsWiped passed" << std::endl;
}

void testSecureStringMovedFromIsWiped() {
  alignas(secure_string) StringStorage from{};
  {
    auto *a = new (from.data()) secure_string(kShortSecret);
    const secure_string b(std::move(*a));
    EXPECT(b == kShortSecret);
    EXPECT(a->empty());
    EXPECT(!storage_holds(from, kShortSecret));  // while a is alive
    a->~secure_string();
  }
  {
    auto *a = new (from.data()) secure_string(kShortSecret);
    secure_string b("other value");
    b = std::move(*a);
    EXPECT(b == kShortSecret);
    EXPECT(!storage_holds(from, kShortSecret));
    a->~secure_string();
  }

  std::cout << "testSecureStringMovedFromIsWiped passed" << std::endl;
}

void testSecureStringMoveAssignmentWipesTheOldValue() {
  // A shorter new value would leave the end of the old one in the buffer.
  constexpr const char *old_value = "OLD_SECRET_1234";  // 15: still inline
  alignas(secure_string) StringStorage to{};
  auto *b = new (to.data()) secure_string(old_value);
  secure_string a("new");
  *b = std::move(a);
  EXPECT(*b == "new");
  EXPECT(!storage_holds(to, old_value));
  b->~secure_string();

  std::cout << "testSecureStringMoveAssignmentWipesTheOldValue passed"
            << std::endl;
}

void testSecureStringCopyAssignedAndSwappedAreWiped() {
  alignas(secure_string) StringStorage first{};
  alignas(secure_string) StringStorage second{};
  auto *a = new (first.data()) secure_string(kShortSecret);
  auto *b = new (second.data()) secure_string("OLD_SECRET_1234");
  *a = std::string("x");  // shorter copy: the old tail stays until wiped
  a->swap(*b);
  a->~secure_string();
  b->~secure_string();
  EXPECT(!storage_holds(first, kShortSecret));
  EXPECT(!storage_holds(first, "OLD_SECRET_1234"));
  EXPECT(!storage_holds(second, kShortSecret));
  EXPECT(!storage_holds(second, "OLD_SECRET_1234"));

  std::cout << "testSecureStringCopyAssignedAndSwappedAreWiped passed"
            << std::endl;
}

void testSecureStringAssignAndAllocatorMoveWipe() {
  alignas(secure_string) StringStorage from{};
  {
    auto *a = new (from.data()) secure_string(kShortSecret);
    secure_string b("other value");
    b.assign(std::move(*a));
    EXPECT(b == kShortSecret);
    EXPECT(!storage_holds(from, kShortSecret));
    a->~secure_string();
  }
  {
    auto *a = new (from.data()) secure_string(kShortSecret);
    const secure_string b(std::move(*a), secure_string::allocator_type{});
    EXPECT(b == kShortSecret);
    EXPECT(!storage_holds(from, kShortSecret));
    a->~secure_string();
  }
  {
    // Moving a string into itself through a base_type reference keeps it.
    secure_string s("abc");
    s = std::move(s.append("!"));
    EXPECT(s == "abc!");
    s.assign(std::move(static_cast<secure_string::base_type &>(s)));
    EXPECT(s == "abc!");
  }
  {
    secure_string a(kShortSecret);
    secure_string b("other value");
    swap(a, b);
    EXPECT(a == "other value" && b == kShortSecret);
    a.swap(a);
    EXPECT(a == "other value");
  }

  std::cout << "testSecureStringAssignAndAllocatorMoveWipe passed" << std::endl;
}

void testSecureStringWipeEmptiesAndZeroes() {
  alignas(secure_string) StringStorage storage{};
  auto *s = new (storage.data()) secure_string(kShortSecret);
  s->wipe();
  EXPECT(s->empty());
  EXPECT(!storage_holds(storage, kShortSecret));
  s->append("reusable");
  EXPECT(*s == "reusable");
  s->~secure_string();

  std::cout << "testSecureStringWipeEmptiesAndZeroes passed" << std::endl;
}

void testSecureStringTakingABaseRvalueWipesIt() {
  using base_type = secure_string::base_type;
  alignas(base_type) std::array<unsigned char, sizeof(base_type)> raw{};
  StringStorage storage{};
  {
    auto *plain = new (raw.data()) base_type(kShortSecret);
    const secure_string s(std::move(*plain));
    EXPECT(s == kShortSecret);
    std::copy(raw.begin(), raw.end(), storage.begin());
    EXPECT(!storage_holds(storage, kShortSecret));
    plain->~base_type();
  }
  {
    auto *plain = new (raw.data()) base_type(kShortSecret);
    secure_string s;
    s = std::move(*plain);
    EXPECT(s == kShortSecret);
    std::copy(raw.begin(), raw.end(), storage.begin());
    EXPECT(!storage_holds(storage, kShortSecret));
    plain->~base_type();
  }
  {
    // The old, longer value of the destination must not survive either.
    alignas(secure_string) StringStorage to{};
    auto *s = new (to.data()) secure_string("OLD_SECRET_1234");
    *s = base_type("new");
    EXPECT(*s == "new");
    EXPECT(!storage_holds(to, "OLD_SECRET_1234"));
    s->~secure_string();
  }

  std::cout << "testSecureStringTakingABaseRvalueWipesIt passed" << std::endl;
}

// ---- Secrets passing through the TTLV layer ----
//
// Keys, secret data and passwords are encoded into and decoded from generic
// TTLV Elements. Each scenario below runs a full encode or decode with a
// marker secret and then counts the freed blocks that still hold it. Every
// scenario runs with a 32-byte marker and with a 12-byte one: a string that
// short is kept inside the string object, not in allocator storage, so it is
// found only when the object itself is on the heap and not wiped.

namespace {
  // Values no other data in the test contains. Kept in static storage, so
  // the scan never sees the test's own copy.
  constexpr std::array<unsigned char, 32> kLongMarker{
      0x5A, 0xC3, 0x9E, 0x17, 0x42, 0xB8, 0x6D, 0xF1, 0x08, 0x7C, 0xE5,
      0x33, 0x91, 0x2F, 0xD4, 0x66, 0xA0, 0x1B, 0x87, 0x4E, 0xC9, 0x55,
      0x3A, 0xF6, 0x0D, 0x72, 0xBE, 0x29, 0x94, 0x6B, 0xE0, 0x13,
  };
  constexpr std::array<unsigned char, 12> kShortMarker{
      'h',
      'u',
      'n',
      't',
      'e',
      'r',
      '2',
      '!',
      'Q',
      'z',
      '7',
      '#',
  };

  // Scans frees for @p secret while alive.
  class SecretScan {
  public:
    explicit SecretScan(std::span<const unsigned char> secret) {
      g_scan_hits = 0;
      g_scan_secret = secret;
    }
    ~SecretScan() { g_scan_secret = {}; }
    SecretScan(const SecretScan &) = delete;
    SecretScan &operator=(const SecretScan &) = delete;
  };

  // Runs @p scenario once per marker; throws if any block freed during a run
  // still held the marker.
  template<typename F> void expect_no_unwiped_frees(F &&scenario) {
    for (const std::span<const unsigned char> secret :
         {std::span<const unsigned char>(kLongMarker),
          std::span<const unsigned char>(kShortMarker)}) {
      std::size_t hits = 0;
      {
        SecretScan scan(secret);
        scenario(secret);
        hits = g_scan_hits;
      }
      if (hits != 0) {
        throw std::runtime_error(
            std::to_string(hits) + " freed block(s) still held the " +
            std::to_string(secret.size()) + "-byte secret"
        );
      }
    }
  }

  bool contains(
      std::span<const unsigned char> haystack,
      std::span<const unsigned char> needle
  ) {
    return std::search(
               haystack.begin(), haystack.end(), needle.begin(), needle.end()
           ) != haystack.end();
  }

  secure_bytes get_response_bytes(std::shared_ptr<Element> object) {
    auto payload = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);
    const bool is_secret = object->tag == tag::KMIP_TAG_SECRET_DATA;
    payload->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_OBJECT_TYPE,
            is_secret ? KMIP_OBJTYPE_SECRET_DATA : KMIP_OBJTYPE_SYMMETRIC_KEY
        )
    );
    payload->asStructure()->add(
        Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, "id-1")
    );
    payload->asStructure()->add(std::move(object));

    ResponseMessage resp;
    resp.getHeader().getProtocolVersion().setMajor(1);
    resp.getHeader().getProtocolVersion().setMinor(4);
    resp.getHeader().setTimeStamp(1234567890);
    resp.getHeader().setBatchCount(1);
    ResponseBatchItem item;
    item.setUniqueBatchItemId(1);
    item.setOperation(KMIP_OP_GET);
    item.setResultStatus(KMIP_STATUS_SUCCESS);
    item.setResponsePayload(std::move(payload));
    resp.add_batch_item(item);

    SerializationBuffer buf;
    resp.toElement()->serialize(buf);
    return buf.release();
  }

  std::shared_ptr<Element> key_block_with(
      int32_t key_format, std::span<const unsigned char> material
  ) {
    auto key_block = Element::createStructure(tag::KMIP_TAG_KEY_BLOCK);
    key_block->asStructure()->add(
        Element::createEnumeration(tag::KMIP_TAG_KEY_FORMAT_TYPE, key_format)
    );
    auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
    key_value->asStructure()->add(
        Element::createByteString(tag::KMIP_TAG_KEY_MATERIAL, material)
    );
    key_block->asStructure()->add(key_value);
    return key_block;
  }
}  // namespace

void testGetKeyLeavesNoPlainCopy() {
  expect_no_unwiped_frees([](std::span<const unsigned char> secret) {
    auto key_block = key_block_with(KMIP_KEYFORMAT_RAW, secret);
    key_block->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, KMIP_CRYPTOALG_AES
        )
    );
    key_block->asStructure()->add(
        Element::createInteger(
            tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH,
            static_cast<int32_t>(secret.size() * 8)
        )
    );
    auto symmetric_key = Element::createStructure(tag::KMIP_TAG_SYMMETRIC_KEY);
    symmetric_key->asStructure()->add(key_block);
    const auto bytes = get_response_bytes(symmetric_key);

    ResponseParser parser(bytes);
    const auto item = parser.getResponse<GetResponseBatchItem>(0);
    const Key key = KeyParser::parseGetKeyResponse(item);
    EXPECT(std::ranges::equal(key.value(), secret));
    // The Debug log path formats the whole response.
    EXPECT(!format_ttlv(bytes).empty());
  });

  std::cout << "testGetKeyLeavesNoPlainCopy passed" << std::endl;
}

void testGetSecretLeavesNoPlainCopy() {
  expect_no_unwiped_frees([](std::span<const unsigned char> secret) {
    auto secret_data = Element::createStructure(tag::KMIP_TAG_SECRET_DATA);
    secret_data->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_SECRET_DATA_TYPE,
            static_cast<int32_t>(secret_data_type::KMIP_SECDATA_PASSWORD)
        )
    );
    secret_data->asStructure()->add(
        key_block_with(KMIP_KEYFORMAT_OPAQUE, secret)
    );
    const auto bytes = get_response_bytes(secret_data);

    ResponseParser parser(bytes);
    const auto item = parser.getResponse<GetResponseBatchItem>(0);
    const auto parsed =
        std::make_unique<Secret>(KeyParser::parseGetSecretResponse(item));
    EXPECT(std::ranges::equal(parsed->value(), secret));
    EXPECT(std::ranges::equal(parsed->as_text(), secret, [](char a, auto b) {
      return static_cast<unsigned char>(a) == b;
    }));
    EXPECT(!format_ttlv(bytes).empty());
  });

  std::cout << "testGetSecretLeavesNoPlainCopy passed" << std::endl;
}

void testRegisterKeyLeavesNoPlainCopy() {
  expect_no_unwiped_frees([](std::span<const unsigned char> secret) {
    const Key key(
        secret,
        KeyType::SYMMETRIC_KEY,
        Attributes{}
            .set_algorithm(cryptographic_algorithm::KMIP_CRYPTOALG_AES)
            .set_crypto_length(static_cast<int32_t>(secret.size() * 8))
    );
    RequestMessage request;
    request.add_batch_item(RegisterKeyRequest("name", "group", key));
    const auto bytes = request.serialize();
    EXPECT(contains(bytes, secret));
    EXPECT(!format_request(request).empty());
  });

  std::cout << "testRegisterKeyLeavesNoPlainCopy passed" << std::endl;
}

void testRegisterSecretLeavesNoPlainCopy() {
  expect_no_unwiped_frees([](std::span<const unsigned char> secret) {
    RequestMessage request;
    request.add_batch_item(RegisterSecretRequest(
        "name", "group", secret, secret_data_type::KMIP_SECDATA_PASSWORD
    ));
    const auto bytes = request.serialize();
    EXPECT(contains(bytes, secret));
    EXPECT(!format_request(request).empty());
  });

  std::cout << "testRegisterSecretLeavesNoPlainCopy passed" << std::endl;
}

void testTextStringLeavesNoPlainCopy() {
  // A Text String element (a password) on its own: built, serialized, parsed
  // back and formatted.
  expect_no_unwiped_frees([](std::span<const unsigned char> secret) {
    const std::string_view text(
        reinterpret_cast<const char *>(secret.data()), secret.size()
    );
    const auto element =
        Element::createTextString(tag::KMIP_TAG_PASSWORD, text);
    SerializationBuffer buf;
    element->serialize(buf);
    const auto bytes = buf.release();
    EXPECT(contains(bytes, secret));

    std::size_t offset = 0;
    const auto parsed = Element::deserialize(bytes, offset);
    EXPECT(parsed->stringView() == text);
    EXPECT(!format_element(parsed).empty());
  });

  std::cout << "testTextStringLeavesNoPlainCopy passed" << std::endl;
}

void testPasswordLeavesNoPlainCopy() {
  // The request is on the heap, so the header's own copy of the password is
  // inside a block the hook sees when the request is destroyed.
  expect_no_unwiped_frees([](std::span<const unsigned char> secret) {
    const std::string_view password(
        reinterpret_cast<const char *>(secret.data()), secret.size()
    );
    auto request = std::make_unique<RequestMessage>();
    request->getHeader().setUserName(std::string("alice"));
    request->getHeader().setPassword(password);
    RequestBatchItem item;
    item.setOperation(KMIP_OP_QUERY);
    item.setRequestPayload(
        Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD)
    );
    request->add_batch_item(item);
    const auto bytes = request->serialize();
    EXPECT(contains(bytes, secret));
    EXPECT(!format_request(*request).empty());

    std::size_t offset = 0;
    const auto element = Element::deserialize(bytes, offset);
    const auto parsed =
        std::make_unique<RequestMessage>(RequestMessage::fromElement(element));
    EXPECT(parsed->getHeader().getPassword() == password);
  });

  std::cout << "testPasswordLeavesNoPlainCopy passed" << std::endl;
}

void testBigIntegerLeavesNoPlainCopy() {
  expect_no_unwiped_frees([](std::span<const unsigned char> secret) {
    // A round trip, both accessors and the formatter (which redacts Key
    // Material and reads only its length).
    const auto element =
        Element::createBigInteger(tag::KMIP_TAG_KEY_MATERIAL, secret);
    EXPECT(std::ranges::equal(element->bytesView(), secret));
    EXPECT(!format_element(element).empty());

    SerializationBuffer buf;
    element->serialize(buf);
    const auto bytes = buf.release();
    EXPECT(contains(bytes, secret));
    std::size_t offset = 0;
    const auto parsed = Element::deserialize(bytes, offset);
    EXPECT(parsed->type == static_cast<Type>(KMIP_TYPE_BIG_INTEGER));
    EXPECT(std::ranges::equal(parsed->bytesView(), secret));
    EXPECT(!format_element(parsed).empty());
  });

  // The braced-list overload, and the formatter's unredacted branch.
  const auto listed = Element::createBigInteger(
      tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, {0x01, 0x02}
  );
  EXPECT(listed->bytesView().size() == 2 && listed->bytesView()[1] == 0x02);
  // toBytes() is the documented plain copy, so it is checked outside a scan.
  EXPECT(listed->toBytes() == std::vector<uint8_t>({0x01, 0x02}));
  EXPECT(format_element(listed).find("len=2") != std::string::npos);

  std::cout << "testBigIntegerLeavesNoPlainCopy passed" << std::endl;
}

void testViewsRejectOtherTypes() {
  const auto expect_throws = [](auto &&f) {
    bool threw = false;
    try {
      f();
    } catch (const KmipException &) {
      threw = true;
    }
    EXPECT(threw);
  };
  const auto text = Element::createTextString(tag::KMIP_TAG_PASSWORD, "pw");
  const auto bytes =
      Element::createByteString(tag::KMIP_TAG_KEY_MATERIAL, {0x01, 0x02});
  const auto number =
      Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, 128);
  expect_throws([&] { (void) text->bytesView(); });
  expect_throws([&] { (void) number->bytesView(); });
  expect_throws([&] { (void) bytes->stringView(); });
  expect_throws([&] { (void) number->stringView(); });

  std::cout << "testViewsRejectOtherTypes passed" << std::endl;
}

int main() {
  std::cout << "Running secure_memory tests..." << std::endl;

  try {
    testSecureClearZeroes();
    testHeterogeneousByteCompare();
    testHeterogeneousStringCompare();
    testSecureStringHashAndBaseCopy();
    testReleaseScrubsRetainedCapacity();
    testShrinkReleasesCapacity();
    testSecureBytesScrubbedOnDestruction();
    testSecureBytesScrubbedOnReallocation();
    testSecureStringScrubbedOnDestruction();
    testSecureStringShortValueIsWipedOnDestruction();
    testSecureStringGrownFromShortIsWiped();
    testSecureStringMovedFromIsWiped();
    testSecureStringMoveAssignmentWipesTheOldValue();
    testSecureStringCopyAssignedAndSwappedAreWiped();
    testSecureStringAssignAndAllocatorMoveWipe();
    testSecureStringWipeEmptiesAndZeroes();
    testSecureStringTakingABaseRvalueWipesIt();
    testGetKeyLeavesNoPlainCopy();
    testGetSecretLeavesNoPlainCopy();
    testRegisterKeyLeavesNoPlainCopy();
    testRegisterSecretLeavesNoPlainCopy();
    testTextStringLeavesNoPlainCopy();
    testPasswordLeavesNoPlainCopy();
    testBigIntegerLeavesNoPlainCopy();
    testViewsRejectOtherTypes();

    std::cout << "All secure_memory tests passed" << std::endl;
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Test failed: " << e.what() << std::endl;
    return 1;
  }
}
