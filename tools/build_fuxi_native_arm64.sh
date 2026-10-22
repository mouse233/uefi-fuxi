#!/usr/bin/env bash
# Native Linux/ARM64 host adapter; firmware sources/dependencies stay pinned.
# SPDX-License-Identifier: BSD-2-Clause-Patent
set -euo pipefail
case "$(uname -sm)" in
  "Linux aarch64") ;;
  *) echo 'This helper requires a native Linux aarch64 host.' >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
: "${UNIXNU_ROOT:?Set UNIXNU_ROOT to the pinned UniXNU checkout}"
command -v nasm >/dev/null
command -v clang >/dev/null
command -v lld-link >/dev/null
fuxi_nasm_descriptor=Mu_Basecore/BaseTools/Bin/nasm_ext_dep.yaml
fuxi_nasm_backup=$(mktemp "$PWD/.fuxi-nasm.XXXXXX")
cp "$fuxi_nasm_descriptor" "$fuxi_nasm_backup"
trap 'cp "$fuxi_nasm_backup" "$fuxi_nasm_descriptor"; rm -f "$fuxi_nasm_backup"' EXIT
# The legacy NuGet x86 assembler is not used to assemble AARCH64 firmware.
# Supply the distro's native nasm and keep the ARM64 Mu-Basetools dependency.
python3 - "$fuxi_nasm_descriptor" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
data = p.read_bytes()
old = b'"scope": "edk2-build"'
if data.count(old) != 1:
    raise SystemExit("Unexpected NASM descriptor; review dependency changes")
p.write_bytes(data.replace(old, b'"scope": "fuxi-unused-x86-assembler"'))
PY
export CLANGPDB_AARCH64_PREFIX=aarch64-linux-gnu-
python3 build_uefi.py -d fuxi -r DEBUG "$@"
