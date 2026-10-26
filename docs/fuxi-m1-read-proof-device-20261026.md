# M1 v8 attempt-01 — 2026-10-26

One temporary boot completed 2026-10-26T21:53:19.181421+08:00. Image SHA256
`fdab273913dbe4a7853b9d33ec3c8332b5943aedab344cce5782baf87ec32de8`; source `75a7faca`.
Sending and Booting returned OKAY, exit 0. Serial/product/unlocked/profile and
the exact staged image hash were checked. No flash, erase, slot change,
payload transfer, restart or repeated boot.

The three original photographs are archived locally in this attempt, with
hashes in assessment.json; they are not stored in the source repository.

## M1 observations

- NOP/query/wake-SSU/TUR/capacity and GPT succeeded. LUN0 last=0x3afc3ff,
  block=4096; metadata=0x4000..0x7fff, userdata=0x2f7840..0x3afc3fa.
- Metadata and userdata both report independent-read-proof=Success,
  reads=3/3, distinct-buffers=1. These are three commands with two disjoint
  destination buffers in one boot, not a claim based on cached report replay.
- Metadata SHA256 `e77426cf7e4e7d0c2af46e8c8434a358a6c8f923c7b614ec8a72ec288446e51d`.
- Userdata SHA256 `890d7f621df98d0e652092fd7e35e31f4adf4e72fa654a7eca6796e1d379be33`.
- Metadata F2FS header succeeded; feature=0x499, cp_payload=0, cp=512,
  nat=2560, main=4096. Userdata F2FS header was Not Found; that is not a
  filesystem-damage conclusion or a decryption result.
- UFS stop=1, db=0, tdb=0, run=0, hcs=0x10f, is=0; final poisoned=0,
  ready=0. SMMU slot104/bank68, SID60, final sctlr=0, cbar=0x10000,
  cba2r=1, gfsr=0. FSR=0x400 has no bits in fault mask 0xc00001fe;
  its nonzero format field/FAR alone is not a DMA-fault observation.

The bounded M1 read/repeat/queue-stop scope passes this device attempt.
Independent TWRP block comparison and complete route restoration are not
newly proved. There is no metadata file read, Android decryption, BlockIo
publication, RAM-object load or XNU handoff in this attempt.

## USB observations

ENDTRANSFER still times out on EP0 OUT: DEPCMD=0xd08 (CMDACT set),
PHYCFG=0x00102400 (SUSPHY and ENBLSLPM both clear at the failure),
DSTS=0x0001f958 (USB2 link field 0, no DEVCTRLHLT).
The bounded CPU-view raw samples are:

| Position | Word | Device event |
|---|---|---|
| 80 | 0x00000201 | CONNECT_DONE |
| 84 | 0x00000301 | LINK_STATUS_CHANGE, info 0 |
| 88 | 0x00050301 | LINK_STATUS_CHANGE, info 5 |
| 92 | 0x00000101 | RESET |

All four have bit0=1/category=0. None is an endpoint END completion event.
This does not support the earlier assertion that the observed pending bytes
were an END completion that must be consumed for CMDACT to clear. The count
print and later ring-word sample are separate reads, not an atomic history.

The final photograph shows USB halt timeout DSTS=0x00112a41 (no DEVCTRLHLT),
QUIESCE: Time out, route retained and buffers retained, followed by report
replay. UFS stop is not USB HALTED.

The user heard connection/disconnection sounds before and after timeout.
Windows captured 59 samples (2026-10-26T13:53:19.5495127Z to 2026-10-26T13:58:14.2505033Z),
with no VID_1209 sample. Its new error device was
`Unknown USB Device (Device Descriptor Request Failed)`, VID_0000/PID_0002.
Therefore host attachment/error activity was observed; successful descriptor
retrieval/enumeration to 1209:0001 was not. Polling cannot exclude shorter
unobserved transitions.

## M2 continuation

Feature 0x499 comprises encryption capability, extra attributes, project
quota, quota inodes and verity in Linux v5.15. This is a filesystem capability
set, not proof that every metadata inode is encrypted. M2 v2 records these
known bits for SB/checkpoint bootstrap only; inode policy, journal and file
handling remain unimplemented. Its new observed-profile fixture passes,
and the no-SMC AARCH64 module compiles. No second device boot was performed.

The original v8 image and its bindings remain pinned to 75a7faca; newer M2
source must not be substituted into that image's source qualification.
