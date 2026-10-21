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

## 2026-10-21 hardware result and boot-contract audit

The `55b06fef` image with SHA256
`ad4b4dd30af6736c9c0e6e3e38fe9989715208f7042820d2c1b8759dd43c0cfa`
failed its first hardware test. Transfer succeeded, the host lost USB during
`Booting`, and the screen displayed the bootloader's corrupt-device warning.
No UEFI stage/menu was observed. Initial slot b was later reported unbootable
with a active. The user separately approved restoring b with `set_active b`,
then reported Android recovered after normal reboot. No partition image was
flashed or erased. Temporary boot must not be described as incapable of
changing boot-control state through the bootloader's own failure handling.

UniXNU's overview and current generic `scripts/unixnu/bootimg.py` describe v0.
The fuxi profile is v3; its ABL acceptance is unverified. Do not silently switch
versions or infer the red-screen cause from this difference alone. Verify the
Android container, uncompressed ARM64 shim header, FD and DTB as separate
contracts. BootShim preserves x0 but does not locate/parse the appended DTB.

The tested AOSP-produced v3 image has the correct page-aligned `dummy` ramdisk.
It is five bytes, not the empty ramdisk in the guide's smoke-test workflow.
This discrepancy is unproven as a cause. The auxiliary `mkbootimg_v3.py` packer
and unpacker did have independent ramdisk alignment defects, now covered by
byte-for-byte comparisons with the separate AOSP writer. Fixing that tool does
not change the old tested image or establish a hardware fix.

The bundled DTB capture has a `ddr_size` field of 12, while this user reports
a 24 GB fuxi and Android exposed about 22.6 GiB of RAM. Its memory description
must be recollected/validated for this particular phone before it is used as
physical ownership evidence. Static self-consistency is insufficient. This
input discrepancy has not been established as the cause of the warning.


## 2026-10-21 read-only evidence from the recovered 24 GB device

The phone completed a normal Android boot on slot b. After explicit user
permission, root reads copied boot_b (192 MiB), vendor_boot_b (96 MiB),
init_boot_b (8 MiB), dtbo_b (24 MiB), the live FDT, iomem and kernel logs directly
to the host. No phone-side temporary files, reboot, test boot or boot-control
write were used. Raw captures stay private; only allowlisted metadata, address
ranges and SHA256 values are in `docs/evidence/fuxi-24gb-20261021.json`.

Working Android uses boot header v4: boot_b has a 48,228,864-byte uncompressed
ARM64 kernel and zero ramdisk, init_boot_b supplies the generic ramdisk, and
vendor_boot_b contains 17 concatenated DTBs plus its vendor ramdisk. dtbo_b has
12 entries. This is concrete device evidence, but does not establish whether
ABL also supports the port's v3 temporary boot profile. Do not change the
profile to the generic guide's v0, or to v4, solely because they differ.

Android reports DTB and DTBO index 11. Standard `fdtoverlay` accepts that pair,
but the result still has memory `reg = <0 0 0 0>`, board ID `<0 0>`, and a generic
Kalama v2 model. The live tree contains the fuxi model, board ID and real banks.
Therefore offline overlay success does not reproduce all bootloader fixups.
Do not replace the port DTB with this merged placeholder tree.

The live FDT is 828,811 bytes with `ddr_size = 24`; the bundled capture is
815,093 bytes with `ddr_size = 12`. High bank ranges differ substantially.
One memory bank has zero size in both captures and must not become usable RAM.
Android MemTotal is 23,729,968 KiB (about 22.63 GiB). The root-read FDT SHA256
was independently verified on the phone and matches the binary host copy.
These observations support the reported RAM variant, but are not a license
to expose the high banks to GCD without reservation and handoff analysis.

The live splash reservation matches the current display descriptor exactly:
0xB8000000 + 0x02B00000. This validates that reservation's address/extent for
this capture; pixel format and stride still need their own verification.
Android ramoops occupies 0xA7000000 + 0x00400000, overlapping the port's FD
at 0xA7100000 + 0x00300000. This reflects different stage ownership and alone
does not prove an unsafe allocation. A UEFI persistent logger must not reuse
that Android ramoops range while the FD occupies it. No persistent logger was
enabled. The pstore directory was empty after recovery, so this capture does
not supply the failed UEFI run's early bootloader/SEC trace.

For a new explicitly authorized read-only session on Windows PowerShell 7:

```powershell
# Obtain permission for root reads first; keep the output folder private.
./tools/collect_fuxi_readonly.ps1 -Adb 'C:/path/to/adb.exe' `
  -OutputParent 'D:/private-existing-folder' -ExpectedSlot b -AllowRootReads
```

The collector requires one authorized device, binds operations to its ADB
transport, checks the expected slot before and after, copies binary stdout
without text conversion, and records per-file exit status, size and SHA256.
Android properties serve as routing guards; modules can spoof them, so they
are not independent proof of model, firmware provenance or unlock state.
The original capture path exercised the binary-copy operations on hardware;
the reusable collector additionally passed PowerShell syntax and permission
guard checks. None of this validates a new UEFI image on hardware.
