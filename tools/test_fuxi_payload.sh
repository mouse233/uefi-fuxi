#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
case "$(uname -m)" in
  aarch64|arm64) edk_test_arch=AArch64 ;;
  x86_64) edk_test_arch=X64 ;;
  *) exit 2 ;;
esac
payload_path=$(realpath "$1")
test_binary=$(mktemp)
trap 'rm -f "$test_binary"' EXIT
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -fshort-wchar \
  -I Mu_Basecore/MdePkg/Include -I "Mu_Basecore/MdePkg/Include/$edk_test_arch" \
  tools/tests/test_fuxi_payload_bounds.c -o "$test_binary"
"$test_binary" "$payload_path"
