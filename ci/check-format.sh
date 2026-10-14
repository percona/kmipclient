#!/usr/bin/env bash
# Checks formatting of the new C++ libraries (kmipcore, kmipclient, kmiputil).
# Legacy code (libkmip, kmippp) is intentionally exempt.
# Requires clang-format 22.1.5 on PATH (CI installs it via pipx; locally:
# pip install clang-format==22.1.5).
set -euo pipefail
cd "$(dirname "$0")/.."

ver="$(clang-format --version)"
echo "$ver"
if [[ "$ver" != *"version 22.1.5"* ]]; then
  echo "error: clang-format 22.1.5 required (pipx install clang-format==22.1.5); found: $ver" >&2
  exit 1
fi

if find kmipcore kmipclient kmiputil \( -name '*.hpp' -o -name '*.cpp' \) -print0 \
  | xargs -0r clang-format --dry-run --Werror; then
  echo "formatting OK"
else
  echo "To fix: find kmipcore kmipclient kmiputil \\( -name '*.hpp' -o -name '*.cpp' \\) -print0 | xargs -0 clang-format -i" >&2
  exit 1
fi
