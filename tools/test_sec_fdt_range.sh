#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
case "$(uname -m)" in
  aarch64|arm64) edk_test_arch=AArch64 ;;
  x86_64) edk_test_arch=X64 ;;
  *) exit 2 ;;
esac
test_binary=$(mktemp)
trap 'rm -f "$test_binary"' EXIT
cc -std=c11 -Wall -Wextra -Werror -fshort-wchar \
  -I Mu_Basecore/MdePkg/Include -I "Mu_Basecore/MdePkg/Include/$edk_test_arch" \
  -I Mu_Basecore/ArmPkg/Include -I Silicon/Silicium/SiliciumPkg/Include \
  tools/tests/test_sec_fdt_range.c -o "$test_binary"
"$test_binary"
