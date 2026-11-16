/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/KmipIOException.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

  namespace fs = std::filesystem;

  int find_free_port() {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    socklen_t len = sizeof(addr);
    getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
    const int port = ntohs(addr.sin_port);
    close(fd);
    return port;
  }

  bool port_accepts(int port) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    const bool ok =
        ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
    close(fd);
    return ok;
  }

  class NetClientTlsOptionsTest : public ::testing::Test {
  protected:
    void SetUp() override {
      dir_ = fs::temp_directory_path() /
             ("kmip_tls_opts_" + std::to_string(getpid()));
      fs::create_directories(dir_);
      cert_ = (dir_ / "cert.pem").string();
      key_ = (dir_ / "key.pem").string();
      const std::string cmd =
          "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "
          "/CN=localhost -keyout " +
          key_ + " -out " + cert_ + " >/dev/null 2>&1";
      ASSERT_EQ(std::system(cmd.c_str()), 0) << "openssl req failed";
    }

    void TearDown() override {
      stop_server();
      std::error_code ec;
      fs::remove_all(dir_, ec);
    }

    // extra_args are passed to openssl s_server
    void start_server(const std::vector<std::string> &extra_args) {
      port_ = find_free_port();
      std::vector<std::string> args = {
          "openssl",
          "s_server",
          "-quiet",
          "-accept",
          std::to_string(port_),
          "-cert",
          cert_,
          "-key",
          key_
      };
      args.insert(args.end(), extra_args.begin(), extra_args.end());

      pid_ = fork();
      ASSERT_GE(pid_, 0);
      if (pid_ == 0) {
        const int null_fd = open("/dev/null", O_RDWR);
        dup2(null_fd, 0);
        dup2(null_fd, 1);
        dup2(null_fd, 2);
        std::vector<char *> argv;
        for (auto &a : args) {
          argv.push_back(a.data());
        }
        argv.push_back(nullptr);
        execvp("openssl", argv.data());
        _exit(127);
      }

      for (int i = 0; i < 100; ++i) {
        if (port_accepts(port_)) {
          return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      FAIL() << "s_server did not start";
    }

    void stop_server() {
      if (pid_ > 0) {
        kill(pid_, SIGKILL);
        waitpid(pid_, nullptr, 0);
        pid_ = -1;
      }
    }

    bool try_connect(const kmipclient::NetClient::TlsProtocolOptions &opts) {
      kmipclient::NetClientOpenSSL client(
          "127.0.0.1",
          std::to_string(port_),
          cert_,
          key_,
          cert_,
          2000,
          {false, false},
          opts
      );
      try {
        return client.connect();
      } catch (const kmipclient::KmipIOException &) {
        return false;
      }
    }

    fs::path dir_;
    std::string cert_;
    std::string key_;
    int port_ = 0;
    pid_t pid_ = -1;
  };

  TEST_F(NetClientTlsOptionsTest, GroupMismatchFailsConnect) {
    start_server({"-groups", "X25519"});
    EXPECT_FALSE(try_connect({.groups = "P-256"}));
  }

  TEST_F(NetClientTlsOptionsTest, GroupMatchConnects) {
    start_server({"-groups", "P-256"});
    EXPECT_TRUE(try_connect({.groups = "P-256"}));
  }

  TEST_F(NetClientTlsOptionsTest, DefaultOptionsConnect) {
    start_server({});
    EXPECT_TRUE(try_connect({}));
  }

  TEST_F(NetClientTlsOptionsTest, UnknownGroupNamesOption) {
    start_server({});
    kmipclient::NetClientOpenSSL client(
        "127.0.0.1",
        std::to_string(port_),
        cert_,
        key_,
        cert_,
        2000,
        {false, false},
        {.groups = "NoSuchGroup"}
    );
    try {
      client.connect();
      FAIL() << "expected KmipIOException";
    } catch (const kmipclient::KmipIOException &e) {
      EXPECT_NE(std::string(e.what()).find("groups"), std::string::npos)
          << e.what();
      EXPECT_NE(std::string(e.what()).find("NoSuchGroup"), std::string::npos)
          << e.what();
    }
  }

  TEST_F(NetClientTlsOptionsTest, MinVersion13RejectsTls12Server) {
    start_server({"-tls1_2"});
    EXPECT_FALSE(try_connect({.min_version = "1.3"}));
  }

  TEST_F(NetClientTlsOptionsTest, MinVersion12AcceptsTls12Server) {
    start_server({"-tls1_2"});
    EXPECT_TRUE(try_connect({.min_version = "1.2"}));
  }

  TEST_F(NetClientTlsOptionsTest, InvalidMinVersionNamesOption) {
    start_server({});
    kmipclient::NetClientOpenSSL client(
        "127.0.0.1",
        std::to_string(port_),
        cert_,
        key_,
        cert_,
        2000,
        {false, false},
        {.min_version = "1.1"}
    );
    try {
      client.connect();
      FAIL() << "expected KmipIOException";
    } catch (const kmipclient::KmipIOException &e) {
      EXPECT_NE(std::string(e.what()).find("min_version"), std::string::npos)
          << e.what();
    }
  }

}  // namespace
