/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_TESTS_TEMP_DIR_HPP
#define KMIPCLIENT_TESTS_TEMP_DIR_HPP

#include <cerrno>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <system_error>

#ifdef _WIN32
  #include <cstdio>
  #include <random>
#else
  #include <stdlib.h>
#endif

namespace kmipclient::test {

  /**
   * A new directory in the system temporary directory, with an unpredictable
   * name. On POSIX it is made by mkdtemp() with mode 0700. On Windows
   * create_directory() fails for a name that exists, so the directory is
   * new; it is private only as far as the temporary directory is, which
   * holds for ordinary user accounts but not for service accounts such as
   * SYSTEM (C:\Windows\Temp). It is removed with everything in it on
   * destruction; a failed removal fails the current test.
   */
  class TempDir {
  public:
    TempDir() {
      const auto base = std::filesystem::temp_directory_path();
#ifdef _WIN32
      std::random_device random;
      for (int attempt = 1;; ++attempt) {
        char name[40];
        std::snprintf(
            name, sizeof(name), "kmipclient-test-%08x%08x", random(), random()
        );
        path_ = base / name;
        std::error_code ec;
        if (std::filesystem::create_directory(path_, ec)) {
          break;
        }
        if (ec || attempt == 100) {
          throw std::system_error(
              ec ? ec : std::make_error_code(std::errc::file_exists),
              "create_directory " + path_.string()
          );
        }
      }
#else
      std::string name = (base / "kmipclient-test-XXXXXX").string();
      if (::mkdtemp(name.data()) == nullptr) {
        throw std::system_error(
            errno, std::generic_category(), "mkdtemp " + name
        );
      }
      path_ = name;
#endif
    }
    ~TempDir() {
      std::error_code ec;
      std::filesystem::remove_all(path_, ec);
      if (ec) {
        ADD_FAILURE() << "cannot remove " << path_ << ": " << ec.message();
      }
    }
    TempDir(const TempDir &) = delete;
    TempDir &operator=(const TempDir &) = delete;

    [[nodiscard]] const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
  };

}  // namespace kmipclient::test

#endif  // KMIPCLIENT_TESTS_TEMP_DIR_HPP
