# M1 cached report v2 — 2026-10-26

Image: Mu-fuxi-ufs-m1.img (exact alias Mu-fuxi-usb-ram.img), 1871872 bytes.
SHA256: 2720dbdd9ad49d9cf64fb21703b9dc5ef9459d28777188d20e5a6b37cb3fbae9.
Layers: UEFI UFS diagnostic/report protocol, USB receiver's final park display,
and host build/qualification tools. No XNU/SystemOS payload or kernel change.
The parent image a2b338dc... remains unchanged in its independent output.

## Behavior

The UFS DXE records bounded diagnostic text (48 lines, 192 CHAR16 per line),
then seals it. It displays the report and waits 20 seconds before returning
to DXE dispatch. A boot-services-only report protocol permits the receiver to
replay the sealed text at Park after its stop attempt. Replay has no MMIO,
allocation, cache-maintenance or command-submission dependency. Overflow and
truncation are visibly reported; neither silently implies a complete report.
Snapshot readings include pre/post UFS host state, matching SID 0x60 mappings,
selected SMMU bank/slot, configuration and fault registers. The cached values
are explicitly identified as coming from before USB initialization.

UfsCore.c/h, SMMU planner/configuration, PRDT, queue and timeout/quarantine
policy remain byte-identical to the parent. The reference NativeUFS-fuxi
exact-mapping shortcut and its write-log/root-publication paths were not
imported. USB EP0 and controller-stop implementation are unchanged.

## Build and checks

Container unixnu-fuxi-build-arm64, host x86_64, target AARCH64/CLANGPDB.
Base /work/migration/20261026-upstream/unixnu-ram; device
/work/ramdisk-test/UniXNU-fuxi; EDK2 /work/uefi-fuxi/Mu_Basecore.

```
docker exec -w /work/ramdisk-test/uefi-twrp-data unixnu-fuxi-build-arm64 \
  /opt/fuxi-venv/bin/python3 tools/build_fuxi_ufs_candidate.py \
  --base /work/migration/20261026-upstream/unixnu-ram \
  --device /work/ramdisk-test/UniXNU-fuxi --edk2 /work/uefi-fuxi/Mu_Basecore \
  --output /work/ramdisk-test/uefi-twrp-data/out/<new-output> \
  --ufs-report-hold-seconds 20
```

No-SMC and SCM-query DataPort module builds and full fuxi.dsc/Android-v3
packaging exited 0. The normal orchestrator temporarily applied/reversed its
GIC patch; preexisting EDK2 migration changes were retained. Host D: free
space monitoring kept more than 46 GiB available, above the 12 GiB floor.

All final checks exited 0: SMMU audit, route, receiver, production EP0 (19
cases), controller stop (9 cases), delivered image, and report/EFI binding.
The last check verifies actual FuxiNativeUfsDxe EFI presence in the compressed
delivered FD, protocol identity in both EFI modules, 33 build-source hashes,
test source bindings, and zero SMC instructions in the delivered UFS EFI and
both standalone UFS variants. Original image verifier retains its two-module
schema; report-image-tests.json supplies the additional UFS-module binding.
Cache ASan/UBSan checks passed bounds, CRLF, truncation, overflow, sealing and
repeated immutable replay. M1 modeled controller/9 independent SHA256 vectors
and M0 82 malformed-input fixtures passed. Initial cache-test compilation
exposed system/UEFI NULL macro include-order conflict, corrected before the
successful final run; no production guard was disabled.

Full commands and real exit codes: build-exit-codes.json and check-exit-codes.json;
standalone builds also carry build.json. Reports are source-bound, hardware
results are documented separately below.

## Hardware attempt-01

User authorized the next test. Mutex checks found no active test; Windows
fastboot identified the audited phone, product=fuxi/unlocked=yes. Current
slot a; both slots successful=yes/unbootable=no/retry-count=6. The original
single-boot script had just acquired Linux path discovery in another session;
the isolated adapter initially failed host-only with fastboot not found,
before any device command. Its Windows executable path was corrected without
changing the shared script. Preparation hashes and this failure are preserved.

At 2026-10-26 16:56:29 +08:00 the only actual boot completed with exit 0:

```
fastboot.exe -s <audited-serial> boot D:\Projects\UniXNU\migration\20261026-m1-report-v2\attempt-01\Mu-fuxi-ufs-m1.img
Sending 'boot.img' (1828 KB)                       OKAY [  0.058s]
Booting                                            OKAY [  7.347s]
Finished. Total time: 7.413s
```

IMG_7052..JPG shows early cached report; IMG_7054..JPG shows USB EP0 timeout;
IMG_7055..JPG shows final stop timeout followed by the cached report and STOP.
Original photos and SHA256 are in attempt-01/assessment.json.

Photo observations:

- NOP, power query (0x33), wake SSU, LUN0 TUR (one attempt), capacity and GPT
  succeeded. LUN0 last=0x3afc3ff, block=4096. The production GPT reader verifies
  header/entry-array CRCs and partition bounds before returning success.
- metadata=0x4000..0x7fff, userdata=0x2f7840..0x3afc3fa. userdata bounds match
  the historical record, but block0 magic is 964cc46e 60ab062f rather than the
  old f673c25f 7086bec0. No cause is assigned without an independent current
  read; this does not establish decryption, corruption, or cross-boot stability.
- userdata first-block SHA256:
  ad3ccf81e2258a4754e7c28dcd67866de05dee85b5b732190aa0345395156f4d.
  metadata first-block SHA256:
  e77426cf7e4e7d0c2af46e8c8434a358a6c8f923c7b614ec8a72ec288446e51d.
  These are photographed single-read hashes, not independent reference matches.
- metadata F2FS-header=Success; userdata F2FS-header=Not Found. This is bounded
  header inspection only; neither partition was mounted or decrypted.
- UFS SMMU slot=104, bank=68, pages=128; initially no SID60 match, then one
  exact mapping SMR=80000060/S2CR=00000044. Final SCTLR=0, CBAR=00010000,
  CBA2R=1, GFSR=0. Raw FSR=0x400 is format bits [10:9]=2 and has no bits in
  Linux's ARM_SMMU_CB_FSR_FAULT mask (0xc00001fe). Nonzero FSR alone is not
  a fault, and FAR is not a proven fault address in this snapshot. Definition:
  https://github.com/torvalds/linux/blob/master/drivers/iommu/arm/arm-smmu/arm-smmu.h#L183-L206
- UFS stop=1/db=0/run=0; final tdb=0, HCS=0x10f/IS=0, poisoned=0. This is
  evidence of UFS request-list stop, separate from stopping the USB controller.
- USB S19 success/WAIT/speed=3 twice is followed by EP0 command 0x8 timeout.
  After receive timeout: DWC3 halt timeout DSTS=0010ff11; route retained;
  QUIESCE=Time out; buffers retained. Final cached report replay succeeds,
  followed by USBRAM STOP status=Time out. No HALTED/route restoration proof.

Result: UFS raw read/GPT and queue stop, plus both report display phases,
have hardware evidence. USB enumeration/transfer and clean stop failed.
Cached repetition is not a new storage read. No partition writes, flashing,
erasure, slot changes, payload transfer, restart, or second actual boot were
performed. No /data decryption, BlockIo publication, XNU or system boot claim.
Next work: locate EP0 ENDTRANSFER/reset sequencing and controller halt failure;
obtain independent same-state userdata block comparison before changing UFS
takeover policy. Retain DMA memory and route until actual halt proof.
