# M1 attempt-01 — 2026-10-26 16:27:39 +08:00

Single user-authorized temporary boot of Mu-fuxi-ufs-m1.img, 1867776 bytes.
SHA256: a2b338dcf0ae19c647f92fdd714b5d90284a9faf0427486d452a8fa5f6b3470a.
Layer under test: UEFI native UFS diagnostic and USB receiver. No XNU/SystemOS payload.

Before boot: no active test-usb-ram-full/usb-ram-send/boot-ram-window process;
serial/product/unlocked checks passed. Current slot a; a/b successful=yes,
unbootable=no, retry-count=6. Windows fastboot is used through WSL interop.
The isolated adaptation retains SHA256, verification, usb-ram profile, identity
and single-boot checks. Its source/adaptation hashes are in preparation.json.
Thirty delivered source hashes were rechecked against the isolated UEFI source;
image copy and verification match the qualified candidate. Existing six host
checks/build records exited 0; no firmware/source changes or fresh build here.

Exact invocation from Windows fastboot (recorded by the checked runner):

```
fastboot.exe -s <audited-serial> boot D:\Projects\UniXNU\migration\20261026-m1-test\attempt-01\Mu-fuxi-ufs-m1.img
```

```
Sending 'boot.img' (1824 KB)                       OKAY [  0.065s]
Booting                                            OKAY [  1.341s]
Finished. Total time: 1.414s
```

Exit 0 confirms command completion. The user-supplied IMG_7051..JPG confirms
UEFI receiver S19 success, WAIT 1209:0001, speed=3 twice, existing SMMU context
bank=5 and USB route verification. It then shows command 0x8 on physical EP0
timing out and ENDTRANSFER failure at resource index 0. Windows USB inventory
captured after boot contains no 1209:0001 receiver. Therefore successful host
enumeration/data transfer is not established. No payload was sent.

Source inference: Dwc3SendEpCommand timed out waiting for CMDACT to clear;
Dwc3EndTransfer sets Ep0RestartFailed on EP0 failure, blocking subsequent
EP0 restart. Several callers exist; the photo does not identify the exact
triggering event or hardware root cause. Resource index 0 is explicitly valid
for EP0 OUT in this implementation, so the printed zero is not itself a fault.

The photo does not show FUXIUFS GPT/magic/SHA256/stop readback, QUIESCE Success,
route restoration or HALTED. M1 UFS correctness and clean controller shutdown
remain unverified. No automatic retry, reset, flash, erase, slot change or
partition-write command was performed. Further waiting is not an EP0 recovery.
