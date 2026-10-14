#!/usr/bin/env bash
# Fails when any of the platform-independent unit suites is absent from the
# ctest log, so an accidentally-empty test run cannot pass CI.
set -euo pipefail

log="${1:?usage: check-unit-suites.sh <LastTest.log>}"

status=0
for suite in kmip_core_test kmip_parser_test kmip_serialization_buffer_test IOUtilsTest \
  EncodingTest KeyReaderTest KeyWriterTest KeyGeneratorTest; do
  if ! grep -q "$suite" "$log"; then
    echo "::error::unit suite $suite did not run"
    status=1
  fi
done
exit $status
