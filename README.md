# fuxi TWRP /data → UEFI port (`feat/twrp-data-uefi`)

This branch turns the Xiaomi 13 (`fuxi`, SM8550) UEFI firmware into a **local
loader for Android `/data`**: instead of receiving the two iPadOS images over
USB on every boot (~9.38 GB), UEFI should read them from ordinary files in
`/data`, verify their full SHA256, and publish the existing RAM-object handoff
so the menu → DarwinBoot → XNU path continues unchanged.

The device is unlocked and TWRP (`twrp-3.7.1_12-v9.0_A16-fuxi-skkk.img`) can
decrypt its `/data`; this project re-implements the reading side natively in
UEFI. The design, milestone table and stop conditions live in
[`docs/fuxi-twrp-data-port.md`](docs/fuxi-twrp-data-port.md) — that document is
the entry point, not this README.

## What is implemented

| Milestone | Scope | State |
| --- | --- | --- |
| M0 | Bounded read-only probe: BlockIo discovery, GPT CRC/geometry checks, F2FS header identification, SCM/QSEE discovery | done (host-verified) |
| M1 | Native UFS read-only takeover: idle-gated queue adoption, owned DMA window, SMMU stream 0x60 bypass, GPT + raw-block SHA256 diagnostics | implemented; on-device run in progress |
| M2 | `/metadata` file read (checkpoint/NAT/directory walking) | not started |
| M3 | Key wrapping, ICE slots, metadata decryption via SCM/QSEE | not started |
| M4 | Named `/data` file plaintext with hash comparison | not started |
| M5 | Full object load + RAM publication to the existing handoff | not started |

Main modules under `Platforms/Xiaomi/fuxiPkg/Drivers/`:

- [`FuxiNativeUfsDxe`](Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe) — the
  M1 diagnostic (`UfsCore` is a freestanding command core; `UfsSha256` an
  independent SHA-256). Gated by `FUXI_DATA_PORT_UFS=1`; runs at DXE dispatch,
  ahead of the USB receiver, because a receiver-only image parks inside its
  entry after the 180 s idle window and never reaches ReadyToBoot.
- [`FuxiDataProbeDxe`](Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe) — the
  M0 probe (`FUXI_DATA_PORT_PROBE=1`), whose bounded readers the native driver
  reuses through the same read-callback interface.

## What this branch deliberately does not do

No decryption, no key material handling, no BlockIo publication, no writes to
storage, no SMC calls beyond the opt-in INFO existence query
(`FUXI_DATA_SCM_QUERY=1`). Any command completion doubt quarantines the DMA
window and stops issuing commands. A successful build or a completed diagnostic
is not, by itself, evidence of decryption or of a readable `/data`.

## Hardware findings worth keeping

- UFS PRDT entries are little-endian native words; only UPIU fields are
  big-endian. A big-endian PRDT sends the controller to a swapped DMA address
  and resets the device on the first data-bearing command.
- `Print` (ConOut) does not reach the on-screen boot log; only the debug serial
  does. The diagnostic logs every value through both (`FnuLog`), and
  `FUXI_USB_EP0_TRACE=0` silences the receiver's per-packet EP0 traces so the
  value block survives host enumeration on screen.
- The UFS diagnostic plans its SMMU context bank from the second-highest bank,
  leaving the top bank untouched; the USB route trial then lands on the bank
  ABL left behind. Both coexist in one boot.

## Build and test

Reproduction commands (host tests, container builds, candidate build, the six
delivery checks) are in
[`docs/fuxi-twrp-data-port.md`](docs/fuxi-twrp-data-port.md) §9; candidate
reviews live in `out/<candidate>/REVIEW.md` and the device-side log in the
`UniXNU-fuxi` checkout at `diagnostics/ram-root/usb-bulk.md`. Only
`fastboot boot` is ever used; nothing is flashed.

## Fork notice

This is a personal fork of
[hanzi123-bilp/uefi-fuxi](https://github.com/hanzi123-bilp/uefi-fuxi) (itself
descended from [Project-Silicium/Mu-Silicium](https://github.com/Project-Silicium/Mu-Silicium)).
Only the Xiaomi 13 (`fuxi`) port is worked on here; every other device package
is inherited unchanged and is not maintained. The broader fuxi bring-up is
documented in [`docs/fuxi-development.md`](docs/fuxi-development.md); this
branch carries only the `/data` port on top of it.

## License

All code except drivers in `GPLDrivers` & `GPLApplications` & `GPLLibrary`
directories are licensed under BSD-2-Clause. GPL drivers are licensed under
`GPLv2` or later.
