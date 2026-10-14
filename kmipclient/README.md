# The `kmipclient` library

`kmipclient` is a C++20 library that provides a clean, high-level interface to
KMIP servers.  It wraps the `kmipcore` layer into safe C++ types, hiding buffer
handling and TTLV encoding/decoding details from library users.

Everything lives in the `kmipclient` namespace.

---

## Design goals

1. Easy to use and hard to misuse — forced error handling via exceptions.
2. Hide low-level details (no raw `KMIP` context, no manual buffer management).
3. Minimize manual memory management; prefer stack-allocated objects.
4. Make the library easy to extend.
5. Use only the `kmipcore` layer; no direct dependency on `libkmip` or `kmippp`.
6. Replaceable network communication layer (dependency injection).
7. Testability.

---

## External dependencies

The only external dependency is **OpenSSL** (already required by `kmipcore`).
`KmipClient` itself depends only on `kmipcore`.  The network layer is injected
as an implementation of the `NetClient` interface.  The library ships a
ready-to-use `NetClientOpenSSL` implementation; any custom transport can be
used by implementing the four-method `NetClient` interface.

---

## Public headers

| Header | Purpose |
|---|---|
| `kmipclient/KmipClient.hpp` | Main KMIP operations class |
| `kmipclient/KmipClientPool.hpp` | Thread-safe connection pool |
| `kmipclient/Kmip.hpp` | Simplified facade (bundles `NetClientOpenSSL` + `KmipClient`) |
| `kmipclient/NetClient.hpp` | Abstract network interface |
| `kmipclient/NetClientOpenSSL.hpp` | OpenSSL BIO implementation of `NetClient` |
| `kmipclient/Key.hpp` | Typed key model umbrella header (`Key`, `SymmetricKey`, `PublicKey`, `PrivateKey`, `X509Certificate`) |
| `kmipclient/KmipIOException.hpp` | Exception for network/IO errors |
| `kmipclient/types.hpp` | Type aliases re-exported from `kmipcore` |
| `kmipclient/kmipclient_version.hpp` | Version macros (`KMIPCLIENT_VERSION_STR`) |

---

## High-level design

### `NetClient` interface

Abstract base class for network transport.  Defines four virtual methods and
optional TLS verification controls:

```cpp
virtual bool connect();
virtual void close();
virtual int  send(std::span<const std::uint8_t> data);
virtual int  recv(std::span<std::uint8_t> data);

virtual void set_tls_verification(TlsVerificationOptions options) noexcept;
virtual TlsVerificationOptions tls_verification() const noexcept;
```

`NetClientOpenSSL` is the ready-to-use implementation based on OpenSSL BIO.

`TlsVerificationOptions` defaults to secure verification:

```cpp
NetClient::TlsVerificationOptions{
    .peer_verification = true,
    .hostname_verification = true,
}
```

This means the server certificate chain is validated against the configured CA
file, and the certificate must also match the requested host name (or IP
address).  These checks can be relaxed for lab/self-signed environments; see
[`TLS verification controls`](#tls-verification-controls) below.

### `KmipClientPool`

Thread-safe connection pool for high-concurrency scenarios.  Each thread borrows
a `KmipClient` for the duration of one or more KMIP operations and returns it
automatically via RAII:

```cpp
KmipClientPool pool({
    .host = "kmip-server",
    .port = "5696",
    .client_cert = "/path/to/cert.pem",
    .client_key  = "/path/to/key.pem",
    .server_ca_cert = "/path/to/ca.pem",
    .timeout_ms  = 5000,
    .max_connections = 8
});

// Blocking borrow (waits until available)
auto conn = pool.borrow();
auto id   = conn->op_create_aes_key("mykey", "mygroup");
// conn returns automatically when it goes out of scope

// Timed borrow (timeout after duration)
auto conn_timed = pool.borrow(std::chrono::seconds(10));

// Non-blocking variant (returns nullopt if exhausted and at capacity)
if (auto conn_opt = pool.try_borrow()) {
    auto id = conn_opt->op_create_aes_key("key", "group");
}
```

**Pool configuration validation:**
- `max_connections` must be greater than zero
- Throws `kmipcore::KmipException` if invalid
- Default: 16 simultaneous connections

Connection health tracking:
```cpp
try {
    auto conn = pool.borrow();
    conn->op_some_operation();
} catch (const std::exception &e) {
    conn.markUnhealthy();  // Pool discards connection on return
    throw;
}
```

### `KmipClient`

The main KMIP protocol client.  It can be constructed either with a reference
to an already-created `NetClient` instance (dependency injection) or from a
`std::shared_ptr<NetClient>` when shared ownership is preferred:

```cpp
NetClientOpenSSL net_client(host, port, client_cert, client_key, server_ca, timeout_ms);
net_client.connect();

KmipClient client(net_client);          // reference-based
KmipClient client2(net_client, logger); // with protocol logger
```

```cpp
auto transport = std::make_shared<NetClientOpenSSL>(
    host, port, client_cert, client_key, server_ca, timeout_ms
);
transport->connect();

auto client = KmipClient::create_shared(transport, logger);
// client is std::shared_ptr<KmipClient>
```

Copy and move are disabled on `KmipClient` itself, but shared-handle usage is
supported via `KmipClient::create_shared(...)` for pointer-centric integrations
(such as migrations from `kmippp::context`).

#### Move semantics

`KmipClient` is move-only (non-copyable), enabling efficient ownership transfer:

```cpp
std::unique_ptr<KmipClient> client = std::make_unique<KmipClient>(
    net_client, logger, version, true  // close_on_destroy parameter
);
// or
auto my_client = KmipClient::create_shared(net_client, logger, version, false);
// is std::shared_ptr<KmipClient>
```

#### Transport lifetime control

Set the `close_on_destroy` parameter during construction to control whether the destructor closes the transport:

```cpp
// Close transport on destruction (default)
KmipClient client(net_client);

// Keep transport alive after client destruction
KmipClient client(net_client, logger, version, false);
```

### `Kmip` façade

`Kmip` bundles `NetClientOpenSSL` + `KmipClient` into a single object for the
common case where OpenSSL BIO transport is sufficient:

```cpp
Kmip kmip(host, port, client_cert, client_key, server_ca, timeout_ms);
auto key_id = kmip.client().op_create_aes_key("mykey", "mygroup");
```

The façade also accepts an optional final
`NetClient::TlsVerificationOptions` parameter for environments that need to
relax TLS checks without constructing `NetClientOpenSSL` directly.

#### Ownership patterns

`Kmip` supports both value-based and shared-ownership patterns:

**Stack-allocated (automatic cleanup):**
```cpp
Kmip kmip(host, port, cert, key, ca, 5000);  // close_on_destroy defaults to true
auto key_id = kmip.client().op_create_aes_key("k", "g");
// kmip destroyed on scope exit; transport automatically closed
```

**Stack-allocated (keep transport alive):**
```cpp
Kmip kmip(host, port, cert, key, ca, 5000,
          kmipcore::KMIP_VERSION_1_4, nullptr, {}, false);  // close_on_destroy = false
// Transport stays alive after kmip is destroyed
```

**Shared ownership (lifetime management):**
```cpp
auto kmip = Kmip::create_shared(host, port, cert, key, ca, 5000);
auto key_id = kmip->client().op_create_aes_key("k1", "g");
// Transport closes when the last shared_ptr is destroyed
```

`std::shared_ptr<Kmip>` shares ownership/lifetime, but it does **not** make a
single `Kmip`/`KmipClient` instance thread-safe for concurrent operations.

For multithreaded use, choose `KmipClientPool` and borrow one client per thread
(see [Connection pool (multi-threaded)](#connection-pool-multi-threaded)).

#### Transport lifetime control

The `close_on_destroy` parameter (constructor parameter, default `true`) controls
whether the transport is closed when the client/facade is destroyed:

```cpp
// Close transport (default)
Kmip kmip(host, port, cert, key, ca, 5000);

// Keep transport alive after Kmip destruction
Kmip kmip(host, port, cert, key, ca, 5000,
          kmipcore::KMIP_VERSION_1_4, nullptr, {}, false);

// Query the setting
if (kmip.close_on_destroy()) { /* transport will close */ }
```

### TLS verification controls

`kmipclient` now exposes TLS verification explicitly through
`NetClient::TlsVerificationOptions`.

Recommended settings:

| Setting | Use case |
|---|---|
| `{true, true}` | Default and recommended for production |
| `{true, false}` | Self-signed / private CA deployments where the certificate chain is trusted but the certificate host name does not match the endpoint used by the client |
| `{false, false}` | Local development only; disables all server authentication |

`hostname_verification = true` requires `peer_verification = true`.  The
transport rejects the invalid combination `{false, true}`.

#### Strict default (recommended)

```cpp
NetClientOpenSSL net_client(host, port, client_cert, client_key, server_ca, 5000);
net_client.connect();
KmipClient client(net_client);
```

#### Trust the CA, but ignore host name mismatches

This is the common setting for KMIP lab environments that use self-signed or
private-CA certificates issued for a different DNS name than the address the
client actually connects to.  This also covers the typical case where the
server is reached by IP address (`127.0.0.1`) but the certificate contains
only DNS SAN entries (or `CN=hostname`) with no matching IP SAN — in that
case `{true, true}` would fail the IP SAN check and `{true, false}` is the
correct setting.

```cpp
NetClientOpenSSL net_client(host, port, client_cert, client_key, server_ca, 5000);
net_client.set_tls_verification({
    .peer_verification = true,
    .hostname_verification = false,
});
net_client.connect();

KmipClient client(net_client);
```

The same setting can be passed through the `Kmip` façade:

```cpp
Kmip kmip(
    host,
    port,
    client_cert,
    client_key,
    server_ca,
    5000,
    kmipcore::KMIP_VERSION_1_4,
    {},
    {
        .peer_verification = true,
        .hostname_verification = false,
    }
);
```

#### Fully disable verification (development only)

```cpp
NetClientOpenSSL net_client(host, port, client_cert, client_key, server_ca, 5000);
net_client.set_tls_verification({
    .peer_verification = false,
    .hostname_verification = false,
});
net_client.connect();
```

Do **not** use `{false, false}` in production: it disables server certificate
validation and makes TLS vulnerable to active interception.

For a complete runnable sample, see `example_get_tls_verify`, which extends the
basic `example_get` flow with selectable TLS verification modes.

### `Key`

`kmipclient::Key` is the abstract base class for typed key objects. The key
classes only model KMIP objects; reading keys from hex, Base64, raw bytes or
PEM, writing them back, and generating AES keys live in the separate
[`kmiputil`](../kmiputil/README.md) library:

| Helper | Description |
|---|---|
| `kmiputil::KeyReader::aes_from_hex(hex)` | Create AES key from hexadecimal string |
| `kmiputil::KeyReader::aes_from_base64(b64)` | Create AES key from Base64 string |
| `kmiputil::KeyReader::aes_from_value(bytes)` | Create AES key from raw bytes |
| `kmiputil::KeyReader::from_PEM(pem)` | Parse PEM into `X509Certificate` / `PublicKey` / `PrivateKey` / `SymmetricKey` |
| `kmiputil::KeyWriter::to_hex(key)` / `to_base64(key)` / `to_PEM(key)` | Serialize a key |
| `kmiputil::KeyGenerator::generate_aes(size)` | Generate a random AES key (128/192/256 bits) |

`op_get_key(...)` returns `std::unique_ptr<Key>` (polymorphic typed key).
All derived key types expose these common `Key` accessors:

| Method | Return type | Description |
|---|---|---|
| `value()` | `const std::vector<unsigned char> &` | Raw key bytes |
| `type()` | `KeyType` | Key family (`SYMMETRIC_KEY`, `PUBLIC_KEY`, …) |
| `algorithm()` | `cryptographic_algorithm` | KMIP cryptographic algorithm enum |
| `usage_mask()` | `cryptographic_usage_mask` | KMIP usage mask flags |
| `attributes()` | `const std::unordered_map<std::string, std::string> &` | Full attribute map |
| `attribute_value(name)` | `const std::string &` | Single attribute by name (see below) |

#### `attribute_value` — no-throw behaviour

`attribute_value` is `noexcept`.  When the server did not return the requested
attribute it returns a reference to a static empty string rather than throwing:

```cpp
auto key  = client.op_get_key(id, /*all_attributes=*/true);
auto name = key->attribute_value(KMIP_ATTR_NAME_NAME);   // "" if not present
auto state = key->attribute_value(KMIP_ATTR_NAME_STATE); // "" if not present
if (name.empty()) { /* attribute was not returned by the server */ }
```

### `Secret`

Objects returned by `op_get_secret` are instances of `kmipcore::Secret`:

| Method | Return type | Description |
|---|---|---|
| `value()` | `const std::vector<unsigned char> &` | Raw payload bytes |
| `as_text()` | `std::string` | Payload as a UTF-8 string copy |
| `get_state()` | `state` | KMIP lifecycle state |
| `get_secret_type()` | `secret_data_type` | KMIP secret data type (e.g. `KMIP_SECDATA_PASSWORD`) |
| `attributes()` | `const std::unordered_map<std::string, std::string> &` | Full attribute map |
| `attribute_value(name)` | `const std::string &` | Single attribute by name (see below) |

`attribute_value` follows the same no-throw rule as on `Key`: returns `""`
when the attribute was not returned by the server.

`Secret` also provides a static factory for building secrets client-side:

```cpp
auto s = Secret::from_text("s3cr3t!", secret_data_type::KMIP_SECDATA_PASSWORD);
auto id = client.op_register_secret("name", "group", s);
```

### `KmipClientPool`

Thread-safe pool of `KmipClient` connections.  Connections are created lazily
on demand up to `max_connections`.  Threads borrow a client via RAII. The pool
transparently manages TLS connection lifetimes, automatically discarding
unhealthy connections and establishing fresh ones as needed.

**Constructor:**

```cpp
KmipClientPool pool(KmipClientPool::Config{
    .host            = "kmip-server",
    .port            = "5696",
    .client_cert     = "/path/to/cert.pem",
    .client_key      = "/path/to/key.pem",
    .server_ca_cert  = "/path/to/ca.pem",
    .timeout_ms      = 5000,
    .max_connections = 8,
    .logger          = nullptr,  // optional: pass shared_ptr<kmipcore::Logger>
    .version         = kmipcore::KMIP_VERSION_1_4,
    .tls_verification = {
        .peer_verification = true,
        .hostname_verification = false,
    },
});
```

**Borrow variants:**

All borrow calls are non-blocking internally; actual network operations (TLS handshake)
may take time but are not interruptible once started.

```cpp
// Blocking: waits indefinitely until a connection becomes available
auto conn = pool.borrow();

// Timed: throws kmipcore::KmipException on timeout
auto conn = pool.borrow(std::chrono::seconds(10));

// Non-blocking: returns std::nullopt if no connection available and at capacity
auto opt_conn = pool.try_borrow();
if (opt_conn) {
  auto key_id = opt_conn->op_create_aes_key("k", "g");
}
```

**Use pattern (RAII guard):**

```cpp
// In any thread:
{
  auto conn   = pool.borrow();                       // blocks if all busy
  auto key_id = conn->op_create_aes_key("k", "g");
  // conn returned to pool automatically on scope exit
}
```

**Error handling with unhealthy connections:**

If a KMIP operation throws an unrecoverable exception, mark the connection
unhealthy before the guard goes out of scope so the pool discards the connection
(freeing one slot for a fresh connection next time):

```cpp
try {
  auto conn = pool.borrow();
  conn->op_get_key(id);
} catch (const std::exception &e) {
  conn.markUnhealthy();  // pool will discard this connection
  throw;
}
```

**Diagnostic accessors:**

```cpp
std::cout << "Available: " << pool.available_count() << '\n';
std::cout << "Total:     " << pool.total_count() << '\n';
std::cout << "Limit:     " << pool.max_connections() << '\n';
```

`BorrowedClient` also provides `isHealthy()` to check the health state and
`markUnhealthy()` to indicate that the connection should be discarded on return.

### `KmipIOException`

Thrown for network/IO errors (TLS handshake failure, send/receive error).
Inherits from `kmipcore::KmipException` so a single `catch` clause handles
both protocol and transport errors.

---

## Available KMIP operations

All operations are methods of `KmipClient`.  They throw `kmipcore::KmipException`
(or `KmipIOException` for transport errors) on failure.

| Method | Description |
|---|---|
| `op_create_aes_key(name, group)` | Server-side AES-256 key generation (KMIP CREATE) |
| `op_register_key(name, group, key)` | Register an existing key (KMIP REGISTER) |
| `op_register_secret(name, group, secret)` | Register a secret / password |
| `op_get_key(id [, all_attributes])` | Retrieve key object (`std::unique_ptr<Key>`) with optional attributes |
| `op_get_secret(id [, all_attributes])` | Retrieve a secret / password |
| `op_activate(id)` | Activate an entity (pre-active → active) |
| `op_revoke(id, reason, message, time)` | Revoke/deactivate an entity |
| `op_destroy(id)` | Destroy an entity (must be revoked first) |
| `op_locate_by_name(name, object_type)` | Find entity IDs by name |
| `op_locate_by_group(group, object_type [, max_ids])` | Find entity IDs by group |
| `op_all(object_type [, max_ids])` | Retrieve all entity IDs of a given type |
| `op_discover_versions()` | Discover KMIP protocol versions advertised by the server |
| `op_query()` | Query server capabilities, supported operations/object types, and server metadata |
| `op_get_attribute_list(id)` | List attribute names for an entity |
| `op_get_attributes(id, attr_names)` | Retrieve specific attributes by name |

### Interoperability notes (KMIP 2.0 / pyKMIP)

- For consistent behavior across servers, register objects first and then call
  `op_activate(id)` explicitly as a separate step.
- `Get Attributes` is version-aware: KMIP 1.x uses `Attribute Name`, while
  KMIP 2.0 uses spec-correct `Attribute Reference` selectors.
- Some servers omit `Operation` and/or `Unique Batch Item ID` in responses.
  The parser tolerates this and uses request-derived hints for correlation and
  error formatting.

---

## Usage examples

### Get a symmetric key

```cpp
#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
using namespace kmipclient;

NetClientOpenSSL net_client(host, port, client_cert, client_key, server_ca, 200);
KmipClient client(net_client);

try {
  auto key = client.op_get_key(id, /*all_attributes=*/true);
  // key->value()               → raw key bytes (std::vector<uint8_t>)
  // key->algorithm()           → cryptographic_algorithm enum
  // key->usage_mask()          → cryptographic_usage_mask flags
  // key->attribute_value(name) → attribute string, "" if absent (noexcept)
  auto state = key->attribute_value(KMIP_ATTR_NAME_STATE);
  auto kname = key->attribute_value(KMIP_ATTR_NAME_NAME);
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
}
```

### Get a secret / password

```cpp
auto secret = client.op_get_secret(id, /*all_attributes=*/true);
// secret.as_text()              → payload as std::string
// secret.get_state()            → KMIP lifecycle state
// secret.get_secret_type()      → KMIP secret data type
// secret.attribute_value(name)  → attribute string, "" if absent (noexcept)
```

### Create an AES-256 key on the server

```cpp
#include "kmipclient/Kmip.hpp"
using namespace kmipclient;

Kmip kmip(host, port, client_cert, client_key, server_ca, 200);
auto key_id = kmip.client().op_create_aes_key("mykey", "mygroup");
```

### Create a client with hostname verification disabled

```cpp
Kmip kmip(
    host,
    port,
    client_cert,
    client_key,
    server_ca,
    5000,
    kmipcore::KMIP_VERSION_1_4,
    {},
    {
        .peer_verification = true,
        .hostname_verification = false,
    }
);

auto key_id = kmip.client().op_create_aes_key("mykey", "mygroup");
```

### Register an existing key

```cpp
NetClientOpenSSL net_client(host, port, client_cert, client_key, server_ca, 200);
KmipClient client(net_client);

auto generated = kmiputil::KeyGenerator::generate_aes(aes_key_size::AES_256);
auto id = client.op_register_key("mykey", "mygroup", generated);
auto fetched = client.op_get_key(id);

client.op_revoke(
    id,
    revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE,
    "cleanup",
    0
);
client.op_destroy(id);
```

### Register a secret / password

```cpp
Kmip kmip(host, port, client_cert, client_key, server_ca, 200);
auto s  = Secret::from_text("s3cr3t!", secret_data_type::KMIP_SECDATA_PASSWORD);
auto id = kmip.client().op_register_secret("mysecret", "mygroup", s);
auto fetched = kmip.client().op_get_secret(id);

kmip.client().op_revoke(
    id,
    revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE,
    "cleanup",
    0
);
kmip.client().op_destroy(id);
```

### Lifecycle: activate → revoke → destroy

```cpp
client.op_activate(id);
client.op_revoke(id, revocation_reason_type::KMIP_REVOKE_UNSPECIFIED, "Deactivate", 0L);
client.op_destroy(id);
```

### Locate entities by name or group

```cpp
auto ids = client.op_locate_by_name("mykey", KMIP_OBJTYPE_SYMMETRIC_KEY);
auto all = client.op_all(KMIP_OBJTYPE_SYMMETRIC_KEY);
auto grp = client.op_locate_by_group("mygroup", KMIP_OBJTYPE_SYMMETRIC_KEY);
```

### Retrieve attributes

```cpp
auto attr_names = client.op_get_attribute_list(id);
auto attrs      = client.op_get_attributes(id, attr_names);
```

### Discover supported KMIP protocol versions

```cpp
auto versions = client.op_discover_versions();
for (const auto &v : versions) {
  std::cout << "KMIP " << v.getMajor() << '.' << v.getMinor() << '\n';
}
```

### Query server capabilities and metadata

```cpp
auto info = client.op_query();
std::cout << "Vendor: " << info.vendor_name << '\n';
std::cout << "Server: " << info.server_name << '\n';
std::cout << "Supported operations: " << info.supported_operations.size() << '\n';
std::cout << "Supported object types: " << info.supported_object_types.size() << '\n';
```

### Protocol logging

Pass any `kmipcore::Logger`-derived instance to enable TTLV message logging:

Sensitive KMIP fields are redacted by default in these formatted dumps.

At minimum, the formatter redacts credentials, key material, and secret
payload structures (for example `Username`, `Password`, `Credential Value`,
`Key Material`, `Key Value`, and `Secret Data`).

Malformed TTLV input also fails closed: the formatter reports the parse error
without dumping raw bytes.

Redaction is applied to formatter output itself, so it remains in effect for
all `KmipClient` protocol logs produced by `IOUtils::log_debug(...)`.

```cpp
class StdoutLogger final : public kmipcore::Logger {
public:
  bool shouldLog(kmipcore::LogLevel) const override { return true; }
  void log(const kmipcore::LogRecord &r) override {
    std::cout << '[' << kmipcore::to_string(r.level) << "] "
              << r.component << ' ' << r.event << '\n' << r.message << '\n';
  }
};

auto logger = std::make_shared<StdoutLogger>();
KmipClient client(net_client, logger);
```

### Connection pool (multi-threaded)

```cpp
#include "kmipclient/KmipClientPool.hpp"
using namespace kmipclient;

KmipClientPool pool(KmipClientPool::Config{
    .host = host, .port = port,
    .client_cert = cert, .client_key = key, .server_ca_cert = ca,
    .timeout_ms = 5000, .max_connections = 8,
    .tls_verification = {
        .peer_verification = true,
        .hostname_verification = false,
    },
});

std::vector<std::thread> threads;
for (int i = 0; i < 16; ++i) {
  threads.emplace_back([&pool, i] {
    auto conn   = pool.borrow(std::chrono::seconds(10));
    auto key_id = conn->op_create_aes_key("key_" + std::to_string(i), "group");
    std::cout << "thread " << i << " → " << key_id << '\n';
  });
}
for (auto &t : threads) t.join();
```

---

## Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

The library requires **C++20** and **OpenSSL**.

### AddressSanitizer build

Pass `-DWITH_ASAN=ON` to instrument the library and all its consumers.  To
also instrument the full dependency chain (`kmipcore`, standard C++ runtime
included) supply the ASAN flags globally:

```bash
cmake -DBUILD_TESTS=ON -DWITH_ASAN=ON \
      -DCMAKE_BUILD_TYPE=Debug \
      "-DCMAKE_CXX_FLAGS=-fsanitize=address -fno-omit-frame-pointer" \
      "-DCMAKE_C_FLAGS=-fsanitize=address -fno-omit-frame-pointer" \
      "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address" \
      ..
cmake --build . --target kmipclient_test
```

---

## Integration testing

Tests use the Google Test framework (fetched automatically when
`BUILD_TESTS=ON`).

1. Export connection variables:

```bash
export KMIP_ADDR=127.0.0.1
export KMIP_PORT=5696
export KMIP_CLIENT_CA=/path/to/client_cert.pem
export KMIP_CLIENT_KEY=/path/to/client_key.pem
export KMIP_SERVER_CA=/path/to/server_cert.pem
# Optional: enable KMIP 2.0 integration suite
export KMIP_RUN_2_0_TESTS=1
```

For the local certificate layout commonly used in development, this becomes:

```bash
export CERTS_DIR=/tmp/certs
export KMIP_ADDR="127.0.0.1"
export KMIP_PORT="5696"
export KMIP_CLIENT_CA="$CERTS_DIR/mysql-client-cert.pem"
export KMIP_CLIENT_KEY="$CERTS_DIR/mysql-client-key.pem"
export KMIP_SERVER_CA="$CERTS_DIR/vault-kmip-ca.pem"
# Optional: enable KMIP 2.0 integration suite
export KMIP_RUN_2_0_TESTS=1
```
The library is tested with following KMIP servers:

PyKMIP, Hashi Corp Vault, Fortanix DSM in KMD mode, Cosmic KMS server with KMIP mode.

2. Configure and build:

```bash
cmake -DBUILD_TESTS=ON ..
cmake --build .
```

3. Run:

```bash
ctest --output-on-failure
# or directly:
./kmipclient/kmipclient_test
```

When `KMIP_RUN_2_0_TESTS` is not set to `1`, the KMIP 2.0 integration suite
is excluded via GoogleTest filter (`-KmipClientIntegrationTest20.*`).

The KMIP 1.4 integration suite includes enabled tests for:

- `KmipClientIntegrationTest.RegisterThenActivateSymmetricKey`
- `KmipClientIntegrationTest.RegisterThenActivateSecret`

4. Run with AddressSanitizer (requires the ASAN build above):

```bash
ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:print_stats=1" \
  ./kmipclient/kmipclient_test
```

---

## Example programs

| Binary | Description |
|---|---|
| `example_create_aes` | Create a server-side AES-256 key |
| `example_register_key` | Generate local AES-256 key, register it, fetch it, then revoke+destroy |
| `example_register_secret` | Generate local secret, register it, fetch it, then revoke+destroy |
| `example_get` | Retrieve a symmetric key by ID |
| `example_get_tls_verify` | Retrieve a symmetric key by ID while explicitly selecting TLS verification mode (`strict`, `no-hostname`, or `insecure`) |
| `example_get_logger` | Same as `example_get` with protocol-level TTLV logging |
| `example_get_secret` | Retrieve a secret by ID |
| `example_get_name` | Retrieve a key name attribute |
| `example_get_attributes` | List and print all attributes of a key |
| `example_get_all_ids` | List all symmetric-key and secret IDs on the server |
| `example_activate` | Activate (pre-active → active) a key or secret |
| `example_revoke` | Revoke / deactivate a key or secret |
| `example_destroy` | Destroy a revoked key or secret |
| `example_locate` | Find entity IDs by name |
| `example_locate_by_group` | Find entity IDs by group |
| `example_supported_versions` | Discover and print protocol versions advertised by server |
| `example_query_server_info` | Query and print supported operations/object types and server metadata |
| `example_pool` | Multi-threaded pool demo (concurrent key creation) |

All examples follow the same argument pattern:

```
<example_binary> <host> <port> <client_cert> <client_key> <server_ca_cert> [extra args…]
```

`example_get_tls_verify` adds two required trailing arguments beyond the common
connection parameters:

```
example_get_tls_verify <host> <port> <client_cert> <client_key> <server_ca_cert> <key_id> <mode: strict, no-hostname, insecure>
```
