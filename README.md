# kmipclient

A modern C++20 client implementation of the Key Management Interoperability
Protocol (KMIP), an [OASIS][oasis] communication standard for managing objects
stored in key management systems. It supports KMIP 1.4 and 2.0 and is tested
against PyKMIP, HashiCorp Vault, Fortanix DSM, and Cosmian KMS.

The project consists of two libraries:

* **`kmipcore`** — the protocol layer: typed KMIP model, TTLV
  serialization/parsing, request/response classes. No network code.
* **`kmipclient`** — the client layer: high-level KMIP operations, an
  OpenSSL-based transport (replaceable via the `NetClient` interface), and a
  thread-safe connection pool.

Supported operations include creating, registering, retrieving, locating,
activating, revoking, and destroying keys and secrets, as well as querying
server capabilities. See the [kmipclient README](kmipclient/README.md) for
the full API documentation and usage examples.

## Quick example

```cpp
#include "kmipclient/Kmip.hpp"
using namespace kmipclient;

Kmip kmip(host, port, client_cert, client_key, server_ca, timeout_ms);
auto key_id = kmip.client().op_create_aes_key("mykey", "mygroup");
auto key    = kmip.client().op_get_key(key_id);
```

Runnable example programs for every operation live in
[`kmipclient/examples/`](kmipclient/examples).

## Requirements

* A C++20 compiler (GCC or Clang)
* CMake 3.10 or newer
* OpenSSL

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

To install, add `cmake --install build` (use `-DCMAKE_INSTALL_PREFIX` to
choose a custom prefix). A project using the installed package can then do:

```cmake
find_package(kmipclient REQUIRED)
target_link_libraries(your_target PRIVATE kmipclient::kmipclient)
```

Projects that vendor this repository instead (`add_subdirectory`) link the
plain `kmipcore`/`kmipclient`/`kmiputil` target names.

## Tests

Configure with `-DBUILD_TESTS=ON` to build the unit and integration tests
(GoogleTest is fetched automatically):

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The integration tests require a running KMIP server, configured via the
`KMIP_ADDR`, `KMIP_PORT`, `KMIP_CLIENT_CA`, `KMIP_CLIENT_KEY`, and
`KMIP_SERVER_CA` environment variables; they are skipped when these are not
set. Set `KMIP_RUN_2_0_TESTS=1` (at build time too — test discovery filters
on it) to also run the KMIP 2.0 suite.

### AddressSanitizer

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DWITH_ASAN=ON -DBUILD_TESTS=ON
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

## API documentation

Doxygen documentation can be generated with:

```bash
cmake -S . -B build-docs -DBUILD_DOCS=ON
cmake --build build-docs --target doc
```

[oasis]: https://www.oasis-open.org
