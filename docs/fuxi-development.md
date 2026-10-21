# fuxi development and evidence

This is an experimental Xiaomi 13 (fuxi / SM8550) stage-1 port. Compiling an
image does not establish that SEC, DXE, BDS, key input or XNU work on hardware.
The memory table records a particular vendor firmware capture; it must not be
applied to every SM8550 device or every fuxi RAM/firmware variant without checking.

## Baseline and stage-1 boundaries

The initial baseline is `7b7ec153fa41258a5b320ca579afc6e136b11483` on both
`mouse233/uefi-fuxi:fuxi` and `hanzi123-bilp/uefi-fuxi:fuxi`, checked on 2026-10-21.
It supersedes `5bab890` (disable unsafe DT-derived GCD additions) and adds MMIO
apertures for the SPMI key driver. Do not re-enable `FuxiBootMemoryDxe` or
`DarwinBoot` until their DT access and memory ownership are corrected.

SEC enables its MMU inside `InitializeMemory` / `MemoryPeim`. The previous x0
FDT address reported upstream, `0xC5B1D0`, is outside the stage-1 map. Reading
its magic after enabling the MMU can fault even with both DXE consumers disabled.
`SecFdt.h` now checks that a header and its full page-rounded reservation fit
inside mapped RAM before SEC reads/reserves them. Unmapped pointers are logged
and not dereferenced. The raw entry-argument HOB is retained for diagnostics;
it is **not** a mapping, a validated FDT, or permission for consumers to read it.
This guard does not preserve/copy the unmapped tree for XNU. Adjacent descriptors
are deliberately not combined by this conservative check.

The FD is **0xA7100000 + 0x300000 (3 MiB)**. The preceding 1 MiB at 0xA7000000
is a separate reservation. Static validation checks FD/config agreement,
overlaps/alignment, stack bounds, framebuffer capacity and SPMI base coverage.
These checks detect internal inconsistencies; they cannot prove physical memory
ownership, permissions of SPMI registers, panel stride or the current ABL layout.

DEBUG already routes DebugLib through FrameBufferSerialPortLib. Capture the
screen with another camera; do not assume that Android logcat receives UEFI
DEBUG messages. GOP and the debug renderer use the ABL display reservation;
panel stride, color order and continued scanout need real-device confirmation.

## WSL Ubuntu 24.04 build (fresh directory)

Build on the WSL Linux filesystem. The commands below never contact a phone.
They intentionally fail if the destination already exists: inspect an existing
checkout with `git status` before fetching or changing its branch.

```bash
set -euo pipefail
mkdir -p ~/work
cd ~/work
test ! -e uefi-fuxi
git clone --branch fuxi https://github.com/mouse233/uefi-fuxi.git uefi-fuxi
cd uefi-fuxi
git remote add upstream https://github.com/hanzi123-bilp/uefi-fuxi.git
git remote set-url --push upstream DISABLED
git fetch upstream
git rev-list --left-right --count origin/fuxi...upstream/fuxi
# For the initial review branch, use its remote ref once it is published:
git fetch origin dev/fuxi-m0-guards-20261021
git switch --create local-fuxi-review --track origin/dev/fuxi-m0-guards-20261021

git submodule update --init --depth 1 \
  Common/Mu Common/Mu_OEM_Sample Mu_Basecore Silicium-ACPI \
  Silicon/Silicium/OpensslPkg/Library/OpensslLib/openssl

# DEC [Includes] requires MipiSysT/SPDM/unit-test header directories even
# when their implementations are not linked. Initialize the nine direct Mu
# children, without recursively downloading their test dependencies.
git -C Mu_Basecore submodule update --init --depth 1 --jobs 8

sudo apt-get update
sudo apt-get install -y python3-venv device-tree-compiler
python3 -m venv ~/work/fuxi-venv
source ~/work/fuxi-venv/bin/activate
unset CI_BUILD
# Uses apt for host packages, pip inside the active venv. No full OS upgrade.
./setup_env.sh -p apt
export CLANGPDB_AARCH64_PREFIX=aarch64-linux-gnu-

git clone --depth 1 https://github.com/UniXNU/UniXNU UniXNU
mkdir -p UniXNU/drivers
git clone --depth 1 https://github.com/UniXNU/DarwinBoot UniXNU/drivers/DarwinBoot

python3 tools/validate_pkg.py .
python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
bash tools/test_sec_fdt_range.sh
export UNIXNU_ROOT="$PWD/UniXNU"
./build_uefi.py -d fuxi -r DEBUG -c 2>&1 | tee build-fuxi-debug.log
python3 tools/mkbootimg_v3.py info --image Mu-fuxi.img
python3 tools/record_fuxi_build.py --output BuildEvidence
```

On the initially inspected WSL environment, inherited proxy variables pointed
to an unavailable `127.0.0.1:7897`. Direct access worked after unsetting
`HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy` **in the
build shell only**. Do this only if the same failure occurs; no global proxy
configuration needs changing.

If an initial environment setup was interrupted, an existing `Build/` can
make `build_uefi.py` skip setup and report missing Mu external dependencies.
After activating the venv and exporting UNIXNU_ROOT, recover with:

```bash
python3 Platforms/Xiaomi/fuxiPkg/DeviceBuild.py --setup -t DEBUG
python3 Platforms/Xiaomi/fuxiPkg/DeviceBuild.py --update -t DEBUG
```

These update the build environment, not your repository branch.

`setup_env.sh` exports its toolchain prefix in a child shell, so the explicit
`export CLANGPDB_AARCH64_PREFIX=...` above is intentional. Do not use the build
script's `-u` option as a substitute for reviewing upstream changes.

`Mu-fuxi.img` must have Android header v3; the raw FD must be exactly 3,145,728
bytes at `Build/fuxiPkg/DEBUG_CLANGPDB/FV/SILICIUM_UEFI.fd`. The manifest records
the source commit, dirty state, submodule commits, UniXNU/DarwinBoot commits,
Python packages, compiler version, header fields, byte sizes and SHA256 values.
Retain the full build log alongside it. The initial clone commands resolve
external dependencies at build time; to reproduce a recorded build, fetch and
checkout **each exact SHA in its manifest**, including UniXNU and DarwinBoot.
Timestamps embedded in firmware mean matching inputs alone do not guarantee
byte-for-byte identical output. SHA256 identifies the particular delivered image.

## Static checks and CI

`build-fuxi-uefi.yml` builds DEBUG, runs native SEC boundary tests, inspects the
image and uploads firmware plus evidence. Its triggers include shared silicon,
BootShim, build scripts and validator changes. `copy-test.yml` was a duplicate
firmware workflow; it now runs fast Python regression checks as
`fuxi-static-checks`. Neither workflow boots hardware.

## Hardware verification gate (not executed by setup/build/CI)

The first hardware milestone is a visible UEFI/UniXNU menu with usable keys.
Before attempting it, verify the device is fuxi, record the exact software/RAM
variant and boot slot, back up important data and preserve a matching stock
recovery path. Obtain explicit user confirmation for each test session. Prefer
Windows platform-tools for device access and WSL for compilation.

After that confirmation, a test uses only `fastboot boot Mu-fuxi.img` with the
recorded SHA256. No flash, erase, formatting, userdata writes, ABL changes or
bootloader firmware writes are part of this workflow. Temporary boot executes
experimental firmware on a daily-use phone, so it still requires confirmation.
Keep serial numbers out of public logs. `Booting OKAY` proves only that fastboot
accepted the request; it does not prove UEFI started.

Record the entire screen from before launch through the last visible output.
Look for these stage boundaries, retaining the last message if it stalls:

1. Framebuffer DEBUG banner, `MMU: enabled`, `SEC: memory HOBs done`.
2. `SEC: DT header ... outside mapped RAM; not dereferenced`, if x0 is unmapped.
3. `SEC: FV decompressed (Success)` and `SEC: loading DXE core`.
4. DXE driver messages, FuxiKeyInput arbiter/ConIn status, then the menu.
5. Volume up/down and power-as-Enter behavior, repeat/debounce, stable display.

If an exception appears, capture ESR/EC, ELR, FAR and the last loaded driver's
name. Match addresses to the same build's map/debug symbols. Do not infer a
working DRAM layout from a fastboot success line or from another device model.

## Next milestones

M0: establish repeatable SEC -> DXE -> BDS/menu evidence on this device. The
range guard removes a code-level unmapped read; hardware success is unverified.

M1: verify ABL framebuffer format/stride and physical keys, including failed
SPMI access and ExitBootServices polling shutdown.

M2: collect the current device's authoritative RAM and reserved regions; copy
and validate the live FDT before changing page tables, reserve that copy, and
publish only verified DRAM through GCD. Never turn all DT holes into RAM.
Validate RAM Disk/FAT/Block I/O independently.

M3: safely re-enable DarwinBoot, validate the FDT handoff and XNU load windows,
then audit memory-map keys and ExitBootServices ownership. A Linux UEFI build
does not build or demonstrate native XNU/iPadOS.

M4: introduce UFS, USB, clocks and power support in small, separately verified
changes. The initial build deliberately excludes vendor binary drivers.
