#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/ukeystore-test.XXXXXX")"
trap 'rm -rf "$test_dir"' EXIT
umask 077

python3 -m unittest discover -s "$repo_root/tests" -p 'test_*.py' -v

# pkg-config supplies compiler/linker flags for the installed host OpenSSL.
read -r -a crypto_cflags <<< "$(pkg-config --cflags openssl)"
read -r -a crypto_libs <<< "$(pkg-config --libs openssl)"
"${CXX:-c++}" -std=c++17 -Wall -Wextra -Wno-unused-function -Wno-unused-parameter \
    "${crypto_cflags[@]}" "$repo_root/tests/test_chain.cpp" \
    "${crypto_libs[@]}" -o "$test_dir/test_chain"
"$test_dir/test_chain" "$test_dir"
