# M2 non-inline metadata file v1 — 2026-10-27

## 交付与目标

- 分支：`feat/twrp-data-uefi`；UEFI 源码提交 `0586ebe8af5a0ee6fe26ea3271f94ab6cfac5201`。
- 改动层：UEFI 只读诊断目标与交付绑定；未修改 DarwinBoot、XNU 或 Android 分区。
- 候选：`out/m2-noninline-file-v1`；镜像 `Mu-fuxi-m2-metadata.img`，1875968 字节。
- 镜像 SHA256：`6b7e00d7738d7372f6489fb1e39165b56db9034f1e63ad74a0598700d503432d`；两个供检查器使用的镜像别名字节相同。
- 框架提交 `7e237de0aa81a8f38221134c752af2d71236cddc`；设备 board.toml 固定 `1d071dae4618b0676d313cfbe1fc39689e6f139e`。
- 目标：卷相对路径 `/aconfig/maps/system.package.map`，TWRP 当前基准 10,527 字节，SHA256 `14f3d8675423917e383a71c936f4d9a81a29480f34ae3c550e0f4c34e53a0991`。

## 主机验收

- 完整 DEBUG AARCH64 平台及 no-SMC/query 两种独立模块构建退出 0。
- 十二项主机/交付检查全部退出 0：见 `check-exit-codes.json`、`qualification.json`。
- 38 组文件 fixture、14 组引导 fixture、独立 mkfs/sload 填充 F2FS 卷测试均通过；这些是主机证据。
- `FuxiNativeUfsDxe.efi` 的目标路径与 `candidate.json` 一致，实际 EFI 包含在交付 FD；三种 EFI 的 SMC 指令数均为 0。源码/镜像/模块绑定见 `final-source-binding.json`。
- 构建期间 D 盘最低余量 44.86 GiB，高于 12 GiB 保留下限。

## 实机动作与边界

尚未在手机启动本候选。手机上一次报告为 A17 TWRP 且 `/data` 已解密；这不是 fastboot 状态，也不是本候选结果。
下一轮须在确认设备互斥、`fcde91e`、product=fuxi/unlocked、usb-ram profile 和上述精确 SHA 后，使用独立 attempt 目录**仅临时 `fastboot boot` 一次**。不 flash、擦除、改槽、发 USB 载荷或自动重试不明状态。

预期先复现 M1 三次原始读取与 GPT，再出现 `FUXIM2 lookup=Success path=/aconfig/maps/system.package.map`、`file nid=... bytes=10527 inline=0`、完整 `file-read=Success bytes=10527` 和上面的 SHA256，最后 UFS stop 与 `FUXIM2 PARK`。照片需覆盖读取、SHA、停队列、最终驻留。若 F2FS clean checkpoint/policy 不满足，应报告实际状态并停止，不能降级到旧 checkpoint 或跳过保护。

读取长度/摘要必须与同状态 TWRP 基准比较。此候选仍无 Android 密钥解封、dm-default-key/fscrypt、RAM 对象发布或 XNU 接力；USB 接收器故障未重新测试。非空 NAT journal 在当前设备上也没有通过证据。
