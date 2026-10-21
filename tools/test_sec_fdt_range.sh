#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
test_binary=$(mktemp)
trap 'rm -f "$test_binary"' EXIT
cc -std=c11 -Wall -Wextra -Werror -fshort-wchar \
  -I Mu_Basecore/MdePkg/Include -I Mu_Basecore/MdePkg/Include/X64 \
  -I Mu_Basecore/ArmPkg/Include -I Silicon/Silicium/SiliciumPkg/Include \
  tools/tests/test_sec_fdt_range.c -o "$test_binary"
"$test_binary"
