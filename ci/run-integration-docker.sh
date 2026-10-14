#!/usr/bin/env bash
# Runs the test suites locally against a throwaway Cosmian KMS in Docker, the
# same server CI uses (see ci/install-cosmian.sh and ci/start-cosmian.sh), so
# the kmipclient integration tests run instead of being skipped.
#
# Usage: ci/run-integration-docker.sh [options] [-- <extra ctest args>]
#   --build-dir DIR   build directory (default: build/cosmian)
#   --no-build        skip configure/build, only run ctest
#   --keep            leave the KMS container and its work dir after the run
#                     (prints the KMIP_* exports to reuse them by hand)
#   -h, --help
#
# Environment:
#   COSMIAN_IMAGE     KMS image (default: ghcr.io/cosmian/kms:5.28.0, the
#                     version CI pins)
#   CMAKE_ARGS        extra arguments for the first configure, e.g.
#                     "-DWITH_ASAN=ON"
#
# Examples:
#   ci/run-integration-docker.sh
#   ci/run-integration-docker.sh -- -R KmipClientIntegrationTest20
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/build/cosmian"
DO_BUILD=1
KEEP=""
IMAGE="${COSMIAN_IMAGE:-ghcr.io/cosmian/kms:5.28.0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir) BUILD_DIR="$(realpath -m "${2:?--build-dir needs a value}")"; shift 2 ;;
    --no-build) DO_BUILD=""; shift ;;
    --keep) KEEP=1; shift ;;
    -h | --help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --) shift; break ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

for tool in docker openssl python3 cmake ctest; do
  command -v "$tool" > /dev/null || { echo "$tool not found on PATH" >&2; exit 1; }
done

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/kmip-cosmian.XXXXXX")"
CONTAINER="kmip-cosmian-$$"

cleanup() {
  if [ -n "$KEEP" ]; then
    echo "Kept container $CONTAINER and $WORKDIR. Remove with:"
    echo "  docker rm -f $CONTAINER; rm -rf $WORKDIR"
    return
  fi
  docker rm -f "$CONTAINER" > /dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ---- Certificates (CA, server for 127.0.0.1, client) ----
# -extfile instead of -addext/-copy_extensions so OpenSSL 1.1.1 works too.
cd "$WORKDIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout ca.key -out ca.pem \
  -subj '/CN=libkmip-test-ca' 2> /dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj '/CN=127.0.0.1' 2> /dev/null
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 1 -out server.pem -extfile server.ext 2> /dev/null
openssl pkcs12 -export -out server.p12 -inkey server.key -in server.pem \
  -password pass:test
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj '/CN=libkmip-test-client' 2> /dev/null
printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 1 -out client.pem -extfile client.ext 2> /dev/null
chmod 644 server.p12

# ---- Server config (paths are inside the container) ----
cat > kms.toml << 'TOML'
default_username = "admin"

[db]
database_type = "sqlite"
sqlite_path   = "/kms-data/db"
clear_database = true

[tls]
tls_p12_file         = "/kms/server.p12"
tls_p12_password     = "test"
clients_ca_cert_file = "/kms/ca.pem"

[socket_server]
socket_server_start    = true
socket_server_port     = 5696
socket_server_hostname = "0.0.0.0"

[http]
port     = 9998
hostname = "0.0.0.0"

[logging]
rust_log = "info,cosmian_kms=info"
TOML

KMIP_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

# ---- Start the KMS; only the KMIP port, only on loopback ----
docker run -d --name "$CONTAINER" \
  -p "127.0.0.1:$KMIP_PORT:5696" \
  -v "$WORKDIR:/kms:ro" \
  --tmpfs /kms-data:rw,size=256m \
  --entrypoint /bin/cosmian_kms \
  "$IMAGE" -c /kms/kms.toml > /dev/null

# Docker's userland proxy accepts TCP on the published port before the KMS
# listens, so wait for a TLS handshake verified against our CA instead.
ready=""
for _ in $(seq 1 60); do  # ~30 s
  if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2> /dev/null)" != "true" ]; then
    break
  fi
  if openssl s_client -connect "127.0.0.1:$KMIP_PORT" -CAfile ca.pem \
      -cert client.pem -key client.key -verify_return_error \
      < /dev/null > /dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done
if [ -z "$ready" ]; then
  echo "Cosmian KMS did not become ready on 127.0.0.1:$KMIP_PORT" >&2
  docker logs "$CONTAINER" >&2 || true
  exit 1
fi
echo "Cosmian KMS $IMAGE is ready on 127.0.0.1:$KMIP_PORT"

export KMIP_ADDR=127.0.0.1
export KMIP_PORT
export KMIP_CLIENT_CA="$WORKDIR/client.pem"
export KMIP_CLIENT_KEY="$WORKDIR/client.key"
export KMIP_SERVER_CA="$WORKDIR/ca.pem"
export KMIP_TIMEOUT_MS=5000
# Needed at build time too: gtest discovery runs post-build and leaves the
# KMIP 2.0 suite out of the test list when this is unset.
export KMIP_RUN_2_0_TESTS=1

if [ -n "$KEEP" ]; then
  env | grep '^KMIP_' | sed 's/^/export /'
fi

# ---- Build ----
cd "$ROOT"
if [ -n "$DO_BUILD" ]; then
  if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
    generator=()
    command -v ninja > /dev/null && generator=(-G Ninja)
    # shellcheck disable=SC2086  # CMAKE_ARGS is a word list on purpose
    cmake -S "$ROOT" -B "$BUILD_DIR" "${generator[@]}" \
      -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON ${CMAKE_ARGS:-}
  fi
  cmake --build "$BUILD_DIR" -j
fi

# ---- Test, with the same post-checks as CI ----
status=0
ctest --test-dir "$BUILD_DIR" --output-on-failure "$@" || status=$?

log="$BUILD_DIR/Testing/Temporary/LastTest.log"
if grep -qF 'environment variables not configured' "$log"; then
  echo "ERROR: KMIP test environment not configured; integration tests skipped" >&2
  status=1
fi
skipped=$(grep -F '[  SKIPPED ]' "$log" | grep -v -e 'listed below' -e ' ms)$' | sort -u || true)
if [ -n "$skipped" ]; then
  echo "Skipped tests (CI allows only NetClientOpenSSLCanRetryAfterFailedConnect"
  echo "and LocatePageByGroupReportsLocatedItemsWhenServerProvidesIt):"
  echo "$skipped"
fi
exit $status
