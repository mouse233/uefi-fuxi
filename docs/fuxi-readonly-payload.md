# fuxi read-only payload diagnostic

This follows the real-device menu boot of the stage-marker image plus measured
Android OS metadata (`0x220001a7`). The diagnostic is opt-in, fuxi DEBUG only.
It does not enable DarwinBoot, FuxiBootMemoryDxe, vendor hardware, or add memory
to GCD. It does not write any phone partition.

## Handoff

`FuxiPayloadDxe` reads the raw SEC entry-argument HOB only after checking its
length. The FDT header and complete blob must fit inside the existing mapped,
reserved `Kernel` descriptor (`0xA8000000 + 0x10000000`). The blob is copied
before parsing `/chosen/linux,initrd-start` and `linux,initrd-end`. The complete
initrd must fit in that same descriptor and be no larger than 64 MiB. Invalid
or unmapped arguments are logged and skipped, leaving the menu available.

ABL's v3 path prepends the vendor ramdisk **without sector alignment**. The
driver searches each byte for a unique, identified 4 MiB diagnostic FAT16 image
and validates its exact BPB geometry. It never publishes the vendor prefix as
FAT. Identity tags are for discovery, not authentication. A duplicate candidate
is rejected. The FAT is copied into allocated firmware memory and published
through read-only BlockIo; WriteBlocks always returns EFI_WRITE_PROTECTED.
The existing FAT driver and UniXNU's ConnectAll path handle filesystem binding.

The observed x0 for this new build must still be obtained from real-device
logs. The permitted window is a conservative existing mapping, not a guessed
new mapping or permission to dereference a historical address such as 0xC5B1D0.

## Reproduce

Use a native `linux/arm64` Ubuntu 24.04 build host. Keep its data, checkouts,
Python environment and outputs on the external disk. Initialize the same
submodules as `.github/workflows/build-fuxi-uefi.yml` (including Mu_Basecore's
direct children). Install that workflow's build dependencies and `dosfstools`
and `mtools`.

The tested baseline dependencies are UniXNU
`97de9e715e06d77b8ebe7b80f6e556ee7ab9a7e9` and DarwinBoot
`85332b317ee80898fc78939ea64e6ca52d3837a3` (still disabled). Set `UNIXNU_ROOT`
to the UniXNU checkout and activate the project's Python build environment:

```sh
python3 tools/make_fuxi_payload.py --output /work/output/payload.img
bash tools/test_fuxi_payload.sh /work/output/payload.img
bash tools/test_sec_fdt_range.sh
bash tools/build_fuxi_native_arm64.sh --boot-stage-markers --payload-diagnostic
python3 tools/package_fuxi_payload.py --boot Mu-fuxi.img \
  --payload /work/output/payload.img --output /work/output/Mu-fuxi-readonly-payload.img
```

The ARM64 host helper temporarily excludes the unused legacy x86 NASM NuGet
descriptor; its original bytes are restored on exit. The normal EDK2 tool
dependency contains native `Linux-ARM-64` tools. No Intel host tools or emulator
are required. This is a host adaptation, not a firmware feature change.

`make_fuxi_payload.py` uses regular image files and verifies the filesystem,
including the long filename `unixnu.toml`, by reading back the exact config.
The config has no kernel entry and no automatic action; its distinct UI title
is **fuxi payload OK**. Default firmware builds leave the driver disabled.
`package_fuxi_payload.py` preserves the newly built kernel and other header
fields, requires the measured OS metadata, and refuses unknown trailing data.

For another phone or firmware version, recheck its normal boot header and
memory window before changing these bounds/metadata.

## Hardware acceptance

Record the candidate hash and slot flags, perform one temporary boot, and
short-press power through the same existing may-not-work-properly warning if
shown. Success for this stage means the menu uses the FAT config and displays
**fuxi payload OK**, with a volume/config source instead of built-in
configuration. `Booting OKAY` alone is not acceptance. Do not select an action
just to make the screenshot appear different; the title changes on config load.

If the built-in menu returns, capture the earlier `FUXIPAY:` log: it reports
x0, invalid ranges, absence of initrd, candidate discovery and BlockIo install
status. Keep the known menu-only image as the recovery/regression baseline.
Re-enabling DarwinBoot and booting XNU are separate subsequent changes.
