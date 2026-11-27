/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_SECURE_MEMORY_HPP
#define KMIPCORE_SECURE_MEMORY_HPP

#include <algorithm>
#include <cstddef>
#include <functional>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kmipcore {

  /**
   * @brief Overwrite @p n bytes at @p p with zeros in a way the compiler is
   *        not permitted to optimize away.
   *
   * Plain std::memset on a buffer that is about to be freed is a textbook
   * dead-store elimination target: the optimizer sees the memory is never read
   * again and removes the write, leaving secrets in place. secure_clear routes
   * through a platform "explicit" zeroing primitive when available and falls
   * back to a volatile write loop otherwise, so the store always happens.
   *
   * kmipcore intentionally does not depend on OpenSSL, so this does not use
   * OPENSSL_cleanse.
   */
  void secure_clear(void *p, std::size_t n) noexcept;

  /**
   * @brief Allocator that scrubs memory before handing it back to the runtime.
   *
   * Drop-in for the default std::allocator except that deallocate() runs
   * @ref secure_clear over the whole block first. Compose it with the standard
   * containers to get storage whose contents never survive the container:
   * reallocation on growth, moves, and destruction all pass through
   * deallocate() and therefore zero the freed bytes.
   */
  template<typename T> struct secure_allocator {
    using value_type = T;

    secure_allocator() noexcept = default;

    template<typename U>
    secure_allocator(const secure_allocator<U> & /*other*/) noexcept {}

    template<typename U> struct rebind {
      using other = secure_allocator<U>;
    };

    [[nodiscard]] T *allocate(std::size_t n) {
      if (n > (static_cast<std::size_t>(-1) / sizeof(T))) {
        throw std::bad_alloc();
      }
      return static_cast<T *>(::operator new(n * sizeof(T)));
    }

    void deallocate(T *p, std::size_t n) noexcept {
      if (p != nullptr) {
        secure_clear(p, n * sizeof(T));
        ::operator delete(p);
      }
    }
  };

  template<typename T, typename U>
  bool operator==(
      const secure_allocator<T> & /*a*/, const secure_allocator<U> & /*b*/
  ) noexcept {
    return true;
  }

  template<typename T, typename U>
  bool operator!=(
      const secure_allocator<T> & /*a*/, const secure_allocator<U> & /*b*/
  ) noexcept {
    return false;
  }

  /** @brief Byte buffer whose storage is zeroed when freed. */
  using secure_bytes =
      std::vector<unsigned char, secure_allocator<unsigned char>>;

  /**
   * @brief String whose storage is zeroed when it is released.
   *
   * A std::basic_string with @ref secure_allocator, so heap storage is
   * zeroed when it is freed. Short values (up to 15 characters with
   * libstdc++, 22 with libc++) live in a buffer inside the string object
   * instead, which the allocator never sees: the destructor, the move
   * constructors and assignments, assign() from an rvalue and swap() zero
   * that buffer too, so no copy of the value is left in the object once it
   * is destroyed or moved from. While it is alive, clear(), a shorter
   * assignment or growth to the heap may leave bytes in the inline buffer
   * until then; wipe() removes them at once.
   *
   * Moving from a base_type rvalue (a string with the same allocator) wipes
   * that string as well. A std::string has a different allocator: it is
   * copied, not moved, and stays as it was; wiping it is up to its owner.
   *
   * Use it as a std::basic_string, with these limits:
   * - Do not destroy it through a pointer to the base class, and do not slice
   *   it into one: the base class destructor does not zero the inline buffer.
   * - operator+ and substr() return plain base_type strings, which are not
   *   wiped either: construct a secure_string from the result.
   * - The inherited mutators (append(), operator+= ...) return base_type&.
   */
  class secure_string
    : public std::
          basic_string<char, std::char_traits<char>, secure_allocator<char>> {
  public:
    using base_type =
        std::basic_string<char, std::char_traits<char>, secure_allocator<char>>;

    using base_type::base_type;
    secure_string() noexcept = default;
    secure_string(const secure_string &) = default;
    secure_string(secure_string &&other) noexcept
      : base_type(std::move(static_cast<base_type &>(other))) {
      other.wipe();
    }
    secure_string(const base_type &other) : base_type(other) {}
    /** Takes the value of a base_type rvalue and wipes that string. */
    secure_string(base_type &&other) noexcept : base_type(std::move(other)) {
      wipe(other);
    }
    // Allocator-extended moves: they hide the inherited one, which does not
    // wipe the source. The secure_string&& overloads of these and of
    // assign() must be exact matches: otherwise libc++ prefers its
    // string_view template, taking const T&, and copies.
    secure_string(base_type &&other, const allocator_type &alloc)
      : base_type(std::move(other), alloc) {
      wipe(other);
    }
    secure_string(secure_string &&other, const allocator_type &alloc)
      : secure_string(static_cast<base_type &&>(other), alloc) {}

    secure_string &operator=(const secure_string &) = default;
    secure_string &operator=(secure_string &&other) noexcept {
      return *this = static_cast<base_type &&>(other);
    }
    using base_type::operator=;
    /** Takes the value of a base_type rvalue and wipes that string. */
    secure_string &operator=(base_type &&other) noexcept {
      if (static_cast<base_type *>(this) != &other) {
        wipe();
        base_type::operator=(std::move(other));
        wipe(other);
      }
      return *this;
    }

    using base_type::assign;
    /** Like operator=(base_type &&): wipes the moved-from string. */
    secure_string &assign(base_type &&other) noexcept {
      return *this = std::move(other);
    }
    secure_string &assign(secure_string &&other) noexcept {
      return *this = static_cast<base_type &&>(other);
    }

    /**
     * Swaps through moves that wipe what they leave behind; the inherited
     * swap() may copy a short value through an unwiped temporary.
     */
    void swap(secure_string &other) noexcept {
      if (this != &other) {
        secure_string tmp(std::move(other));
        other = std::move(*this);
        *this = std::move(tmp);
      }
    }
    friend void swap(secure_string &a, secure_string &b) noexcept { a.swap(b); }

    ~secure_string() { wipe(); }

    /** @brief Empties the string and zeroes all of its storage. */
    void wipe() noexcept { wipe(*this); }

  private:
    // Empties the string and makes it use its inline buffer again:
    // shrink_to_fit() of an empty string releases heap storage through
    // secure_allocator, which zeroes it. shrink_to_fit() is only a request
    // and is not noexcept in the standard; libstdc++, libc++ and MSVC honour
    // it for an empty string without allocating. Then zeroes the buffer in
    // use (the inline one, or the heap block if it was kept). Growing to the
    // capacity first keeps the zeroing inside [data(), data() + size()], the
    // only range data() gives access to; it does not reallocate.
    static void wipe(base_type &s) noexcept {
      s.clear();
      s.shrink_to_fit();
      s.resize(s.capacity());
      secure_clear(s.data(), s.size());
      s.clear();
    }
  };

  // ---- Heterogeneous comparisons ----
  //
  // secure_bytes / secure_string differ from the default-allocator containers
  // only in their allocator type (and secure_string in its wiping), but the
  // standard comparison operators are not heterogeneous across allocators.
  // These let callers and tests compare secure and plain containers
  // element-wise without copying secrets into a plain one.

  inline bool
      operator==(const secure_bytes &a, const std::vector<unsigned char> &b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
  }
  inline bool
      operator==(const std::vector<unsigned char> &a, const secure_bytes &b) {
    return b == a;
  }
  inline bool
      operator!=(const secure_bytes &a, const std::vector<unsigned char> &b) {
    return !(a == b);
  }
  inline bool
      operator!=(const std::vector<unsigned char> &a, const secure_bytes &b) {
    return !(b == a);
  }

  inline bool operator==(const secure_string &a, const std::string &b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
  }
  inline bool operator==(const std::string &a, const secure_string &b) {
    return b == a;
  }
  inline bool operator!=(const secure_string &a, const std::string &b) {
    return !(a == b);
  }
  inline bool operator!=(const std::string &a, const secure_string &b) {
    return !(b == a);
  }
  // Exact matches for string literals: otherwise the std::string overloads
  // above and std::basic_string's own (const char *) ones are ambiguous for
  // a secure_string.
  inline bool operator==(const secure_string &a, const char *b) {
    return std::string_view(a) == std::string_view(b);
  }
  inline bool operator==(const char *a, const secure_string &b) {
    return b == a;
  }
  inline bool operator!=(const secure_string &a, const char *b) {
    return !(a == b);
  }
  inline bool operator!=(const char *a, const secure_string &b) {
    return !(b == a);
  }

}  // namespace kmipcore

/** Hashes a secure_string like the std::string_view of its value. */
template<> struct std::hash<kmipcore::secure_string> {
  std::size_t operator()(const kmipcore::secure_string &s) const noexcept {
    return std::hash<std::string_view>{}(s);
  }
};

#endif  // KMIPCORE_SECURE_MEMORY_HPP
