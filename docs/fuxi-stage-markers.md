# fuxi three-stage DEBUG image

This diagnostic is for the audited Xiaomi 13 only. It is enabled explicitly:

```sh
UNIXNU_ROOT="$PWD/UniXNU" ./build_uefi.py -d fuxi -r DEBUG -c --boot-stage-markers
python3 tools/record_fuxi_build.py --output BuildEvidence
```

The switch is rejected for RELEASE and other devices before cleanup or patch
operations. The default is off. Make always recompiles the shim when invoked,
so changing the marker switch cannot silently reuse the previous binary.
The manifest detects marker labels in the actual ELF and records the shim hash,
configuration and diagnostic build command.

| Stage | What is emitted | What a positive observation establishes |
| --- | --- | --- |
| 1 | White band, 256 KiB at `0xB8000000` | The shim reached its first diagnostic block after its two header instructions |
| 2 | Gray band, 256 KiB at `0xB8040000`, retaining stage 1 | The FD relocation/bypass and FD instruction-cache maintenance completed; the final branch to FD is next |
| 3 | `SEC: stage 3 entry x0=0x... (not dereferenced)` | SEC reached its framebuffer DEBUG output before `InitializeMemory` changes page tables |

The two bands use continuous memory, not an assumed row stride or resolution.
Their combined `[0xB8000000, 0xB8080000)` range lies inside the reservation
independently confirmed in this phone's live FDT and XBL configuration.
Every color byte is equal, reducing channel-order assumptions. Actual pixel
format, panel visibility and scanout remain hardware dependencies. The band
appearance and size on screen have not been verified on hardware.

SEC clears its framebuffer before the firmware banner, erasing both earlier
bands. Record video continuously from before launch: stages 1/2 may be brief.
A missing band does not prove that its code never ran. Display shutdown,
backlight/scanout changes, early SEC stalls and a missed video frame remain
possible. Stage 3 is not the first SEC instruction and cannot diagnose a
stall before the DEBUG banner on its own.

## Offline validation

The assembly macro uses only x11..x15 and condition flags. It does not touch
x0, the payload pointer x1, relocation state x4/x5, LR or SP, and performs no
calls or stack access. It publishes each band with a barrier and `dc cvac`
using the CTR_EL0 DminLine value. The ARM64 image-size header includes the
larger shim and `_Payload` still equals the complete shim binary size.

`tools/tests/test_boot_shim_markers.py` runs our shim with a synthetic FD in
Unicorn. It checks normal copy, in-place bypass, the real 3 MiB copy length,
64/128-byte cache lines, x0 and preserved registers, framebuffer guard bytes,
exact colors, cache-clean addresses, the final FD branch and header size.
It also checks the disabled binary against the previous 192-byte shim's hash,
rejects an unaudited framebuffer base and exercises make's on -> off rebuild.
Build-scope tests reject other devices/modes and changed reservation limits.

Cache/barrier instructions are recorded and modeled as no-ops in this harness;
CTR_EL0 is synthetic. It does not emulate the display controller, physical
coherency or the full SEC/UEFI firmware, and is not hardware boot validation.
The dedicated `stage-marker-simulation` CI job installs pinned dependencies
and requires these tests to run rather than silently skip.

## Hardware session gate

No device boot is part of building, testing or CI. Obtain explicit permission
for one session and the exact artifact SHA256. Record phone model, unlock
state, current slot and each slot's successful/unbootable/retry flags before
the attempt; preserve the normal-Android recovery path. A slot discrepancy
from the recovered b state stops the launch for review. Use Windows fastboot
and record its full output plus phone video. Do not retry on failure.

Temporary boot can affect boot-control metadata through ABL. No automatic
slot changes, image flashing, erase, userdata logger, ABL modification or
bootloader replacement are authorized by this diagnostic. A recovery action
that writes metadata needs its own explicit approval.

This change keeps Android header v3, gzip, appended bytes, FD base/size and
the memory map. It adds observation points; it does not establish a fix for
the prior corrupt-device warning or justify repeated attempts.
