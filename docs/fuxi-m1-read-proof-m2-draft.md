# M1 read proof and M2 reader draft — 2026-10-26

The current work is the `feat/twrp-data-uefi` port. Its goal is to read the
two plaintext OS/SystemOS files from Android `/data`, verify them in RAM and
publish the existing RAM-object handoff. The Linux v48 system candidate is a
separate work stream.

This change repairs the M1 build and command-ownership regression and prepares
M2 code. New hardware acceptance is pending; host qualification is not a
substitute for the device's repeated-read and stop readbacks.

## M1 changes

- Remove full event dispatch from ENDTRANSFER polling (`38ba3c33`). A RESET
  callback could issue CLEARSTALL against the same busy DEP. The command
  sender now refuses any command while that DEP's CMDACT is set, before writing
  parameters. Failure snapshots retain PHYCFG; no reset clears the EP0 lockout.
- Track the USB fixtures in this repository, with four compile configurations
  including DMA32/trace and ForceRM variants. The production endpoint code and
  production stop function are also exercised together with a pending RESET.
- `FdpVerifyPartitionRead` performs three reads of each selected partition's
  first block into two disjoint caller-owned buffers in one boot. Transport
  errors and differing bytes stop the sequence. The first successful sample
  remains available for SHA256; cached report replay performs no new IO.
- Revoke the read callback when shutdown begins. Once a completion is
  uncertain, do not perform diagnostic UFS/SMMU register reads. DMA remains
  retained. Stop success additionally requires both doorbells zero, run=0 and
  no fatal controller status. `ready=0` after shutdown is intentional.
- Print metadata F2FS feature, cp_payload and CP/NAT/main geometry so the next
  M2 implementation can target observed features without another discovery
  build. This is a header observation, not a filesystem mount.

## Explicit firmware configuration input

`--device-config-ref` selects an immutable `board.toml` from the device Git
repository. The candidate writes that exact input to `config-input/board.toml`
and records its commit and SHA256 in `build-inputs.json`, together with the
framework revision. The shared device checkout is not rolled back or edited.

For this M1 build the qualified format-1 input is
`1d071dae4618b0676d313cfbe1fc39689e6f139e`; the framework is the independently
merged `7e237de0aa81a8f38221134c752af2d71236cddc`. This explicit firmware-only
compatibility path does not complete or silently bypass format-2 migration.
Without the argument the builder still uses the selected device configuration.

Build inside `unixnu-fuxi-build-arm64` (amd64 host, AARCH64 target), after
confirming no other build uses this checkout and D drive stays above 12 GiB:

```sh
docker exec -w /work/ramdisk-test/uefi-twrp-data unixnu-fuxi-build-arm64 \
 /opt/fuxi-venv/bin/python3 tools/build_fuxi_ufs_candidate.py \
 --base /work/migration/20261026-upstream/unixnu-ram \
 --device /work/ramdisk-test/UniXNU-fuxi \
 --device-config-ref 1d071dae4618b0676d313cfbe1fc39689e6f139e \
 --edk2 /work/uefi-fuxi/Mu_Basecore \
 --output /work/ramdisk-test/uefi-twrp-data/out/<new-candidate> \
 --usb-ep0-trace 1 --ufs-report-hold-seconds 20
```

Build the two standalone module variants sequentially with
`tools/build_fuxi_data_port.py --output <candidate>/modules-no-smc` and
`--output <candidate>/modules-scm-query --scm-query`, supplying the same
`--edk2`. Then from WSL run:

```sh
python3 tools/qualify_fuxi_ufs_candidate.py \
 --device ../UniXNU-fuxi --edk2 ../../uefi-fuxi/Mu_Basecore \
 --output out/<new-candidate>
```

The runner records each real exit code, checks the delivered receiver and UFS
EFI against the FD and sources, and checks zero SMC instructions in the UFS
variants. Its USB fixtures do not depend on the untracked device-repository
fixtures. The ordinary SMMU, route, receiver and image checks remain required.

## M1 device acceptance

Use an independent attempt directory and the existing Windows single-boot
adapter with the new image's SHA256/profile/serial checks. Only temporary boot
is used. Before operating the device check the shared test/send/boot processes.

Capture `metadata` and `userdata independent-read-proof=Success reads=3/3`,
both hashes, metadata feature/payload geometry, GPT success and
`stop=1 db=0 run=0 ... tdb=0`, with `poisoned=0`. Read consistency in one boot
does not independently prove the block contents match TWRP; retain that as a
separate comparison. USB enumeration, USB HALTED and UFS queue stop remain
different results. A new host-qualified image is not evidence that the
original Windows enumeration fault has been repaired.

## M2 draft interfaces

Files: `FuxiDataProbeDxe/F2fsReadOnly.c` and `.h`. They compile with the UFS
module but are not called in the M1 diagnostic. There is no file-read success
stub and no device mount or decryption enabled by this change.

| Interface | Implemented draft behavior | Next consumer |
|---|---|---|
| `F2rPrepare` | Bounded partition reads, agreeing superblocks, optional SB CRC, layout checks, two CP pack CRCs/versions, clean latest CP selection, NAT bitmap extraction | Metadata bootstrap; success means only this bootstrap scope |
| `F2rPlanNatRead` | NID bounds, NAT segment interleaving and MSB-first version bitmap addressing | NAT table read planning; journal overlay must precede authoritative lookup |
| `F2rFindDentry` | Plain non-inline directory block records, slot and continuation bitmap checks, duplicate-name rejection | Validated directory inode data blocks; not pathname lookup |

The draft deliberately accepts only 4K logical blocks, a single device,
cp_payload=0, no unknown features (only the optional SB-checksum bit), and
supported clean checkpoints. It rejects recovery/fsck/orphan/compact-summary
extensions. Real metadata feature values must guide subsequent support. A
transport failure is returned directly; it cannot authorize an older CP.

The caller owns `F2R_VOLUME` and a separate 16 KiB workspace. No allocation,
writes, MMIO or security-service operations occur in this parser. On failure
the prepared capability is revoked. NAT planning is not node validation.

Next M2 implementation steps are NAT journal overlays, checked node/inode
resolution, direct/indirect file mapping, inline forms required by the real
metadata, then component/path traversal and exact file bytes. Only a complete
file SHA256 matching a TWRP export closes M2. FBE, wrapped keys and ICE remain M3.

Host tests run production C with ASan/UBSan and independently encoded disk
fixtures, including corrupted CPs, dirty newest CP, version wrap, NAT copy
selection and transport failure. They are format fixtures, not a real-device
filesystem qualification:

```sh
python3 tools/test_fuxi_f2fs.py --edk2 ../../uefi-fuxi/Mu_Basecore \
 --report out/m2-draft-v1/host-tests.json
```

Disk-format facts were checked against the primary Linux v5.15
[format definitions](https://github.com/torvalds/linux/blob/v5.15/include/linux/f2fs_fs.h)
and [checkpoint implementation](https://github.com/torvalds/linux/blob/v5.15/fs/f2fs/checkpoint.c).
This is an original small reader, not copied Linux filesystem source.
