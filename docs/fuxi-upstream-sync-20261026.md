# fuxi upstream integration — 2026-10-26

Merged hanzi123-bilp/uefi-fuxi fuxi 5493eb07. The incoming tree contains the
alternate standalone loader/root-extents experiment, FIEMAP utility, optional
manual CI workflows and a RAM disk scanner. The separate loader carries its
own fixed root-layout/payload and is not the USB RAM handoff or TWRP data path.

Conflict decisions: retain this device's validated FD/memory layout, bounded
SEC FDT reservation and FuxiPayloadDxe dispatch. Do not automatically dispatch
the upstream FuxiRamDiskDxe scanner or publish an unchecked payload-address HOB.
Its source is available for subsequent review. Keep the existing default-off
diagnostic switches. Existing FUXIPAYL packaging and USB receiver guards remain.
No upstream dependabot branch was merged, and no submodule pins were bumped.

Validation: package/memory-map validator; SEC range and payload scanner C tests
with ASan/UBSan and a real identified FAT16 fixture. The alternate loader/CI
root-image recipes were reviewed as a separate path and not built or run.
No new hardware acceptance is asserted.

## feat/twrp-data-uefi validation

Full M1 receiver-only firmware/Android-v3 image built on the current amd64
Linux Docker host with target AARCH64. M0 no-SMC/query module builds succeeded;
all six receiver delivery checks and M0/M1 modeled-host tests exited 0.
Builder reports now preserve both DXE module hashes and host/target architecture.
Candidate REVIEW holds exact image identity. No hardware attempt was performed.
