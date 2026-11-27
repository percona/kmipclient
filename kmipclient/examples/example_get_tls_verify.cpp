
/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
#include "kmipclient/kmipclient_version.hpp"

#include <iostream>
#include <optional>
#include <span>
#include <string_view>

using namespace kmipclient;

namespace {

  void print_hex(std::span<const unsigned char> key) {
    for (auto const &c : key) {
      std::cout << std::hex << static_cast<int>(c);
    }
    std::cout << std::endl;
  }

  std::optional<NetClient::TlsVerificationOptions>
      parse_tls_mode(std::string_view mode) {
    if (mode == "strict") {
      return NetClient::TlsVerificationOptions{
          .peer_verification = true,
          .hostname_verification = true,
      };
    }

    if (mode == "no-hostname") {
      return NetClient::TlsVerificationOptions{
          .peer_verification = true,
          .hostname_verification = false,
      };
    }

    if (mode == "insecure") {
      return NetClient::TlsVerificationOptions{
          .peer_verification = false,
          .hostname_verification = false,
      };
    }

    return std::nullopt;
  }

  void print_usage() {
    std::cerr << "Usage: example_get_tls_verify <host> <port> <client_cert> "
                 "<client_key> "
                 "<server_cert> <key_id> <mode: strict, no-hostname, insecure>"
              << std::endl
              << "  strict       - verify certificate chain and host name/IP "
                 "(default secure mode)"
              << std::endl
              << "  no-hostname  - verify certificate chain only; skip host "
                 "name/IP match"
              << std::endl
              << "  insecure     - disable all TLS server verification "
                 "(development only)"
              << std::endl;
  }

}  // namespace

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT  version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;
  if (argc < 8) {
    print_usage();
    return -1;
  }

  const auto tls_verification = parse_tls_mode(argv[7]);
  if (!tls_verification.has_value()) {
    std::cerr << "Unknown TLS verification mode: '" << argv[7] << "'"
              << std::endl;
    print_usage();
    return -1;
  }

  try {
    NetClientOpenSSL net_client(
        argv[1], argv[2], argv[3], argv[4], argv[5], 200
    );
    net_client.set_tls_verification(*tls_verification);
    net_client.connect();
    KmipClient client(net_client);

    std::string id = argv[6];
    auto key = client.op_get_key(id);
    std::cout << "Key: 0x";
    print_hex(key->value());
    std::cout << "Attributes:" << std::endl;
    for (const auto &[attr_name, attr_value] :
         key->attributes().as_string_map()) {
      std::cout << "  " << attr_name << ": " << attr_value << std::endl;
    }
  } catch (const std::exception &e) {
    std::cerr << "Can not get key with id:" << argv[6] << " Cause: " << e.what()
              << std::endl;
    return 1;
  };

  return 0;
}
