/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/Kmip.hpp"
#include "kmipclient/KmipClient.hpp"
#include "kmipclient/kmipclient_version.hpp"

#include <iomanip>
#include <iostream>
#include <span>

using namespace kmipclient;

namespace {

  void print_hex(std::span<const unsigned char> bytes) {
    for (const auto b : bytes) {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
  }

}  // namespace

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;

  if (argc < 7) {
    std::cerr << "Usage: example_create_aes <host> <port> <client_cert> "
                 "<client_key> <server_cert> "
                 "<key_name>"
              << std::endl;
    return -1;
  }

  try {
    Kmip kmip(argv[1], argv[2], argv[3], argv[4], argv[5], 200);
    auto key_id = kmip.client().op_create_aes_key(
        argv[6],
        "TestGroup",
        aes_key_size::AES_256,
        static_cast<cryptographic_usage_mask>(
            kmipcore::KMIP_CRYPTOMASK_ENCRYPT |
            kmipcore::KMIP_CRYPTOMASK_DECRYPT |
            kmipcore::KMIP_CRYPTOMASK_MAC_GENERATE
        )
    );
    std::cout << "Key ID: " << key_id << std::endl;

    auto key = kmip.client().op_get_key(key_id, true);
    std::cout << "Created key value (hex): ";
    print_hex(key->value());

    std::cout << "Created key attributes:" << std::endl;
    for (const auto &[name, value] : key->attributes().as_string_map()) {
      std::cout << "  " << name << ": " << value << std::endl;
    }

    return 0;
  } catch (std::exception &e) {
    std::cerr << "Can not create key with name:" << argv[6]
              << " Cause: " << e.what() << std::endl;
  }
  return -1;
}
