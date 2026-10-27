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

## attempt-01 临时启动 — 2026-10-27

2026-10-27 10:20:29 +08:00 完成一次 `fastboot boot`：发送 OKAY 0.059 秒、
启动 OKAY 1.644 秒，命令退出 0。启动前确认设备互斥、serial `fcde91e`、
product `fuxi`、unlocked=yes、usb-ram profile、12项检查及精确镜像 SHA。
原始命令与查询见 `attempt-01/device-test.json`。

当前状态为 **等待手机屏幕照片**。主机启动 OKAY 只能证明 fastboot 接受了
临时启动请求，不能据此判定非 inline 文件、UFS 停机或 M2 已通过。
本轮仅一次临时启动；尚未获得文件读取、SHA256、队列停止或 park 的实机观察。

## attempt-01 照片结果 — checkpoint 不满足只读策略

原图 `attempt-01/IMG_7090-original.jpg`，SHA256
`f6c1010e630aea66d14817fd5654dc613bc7b84c875a9f8cdf9b247d03b127ed`；结构化判读见 `assessment.json`。
UFS NOP/power/wake/TUR/capacity/GPT 成功，metadata/userdata 各自独立缓冲区读取 3/3；
首块 SHA 与此前 A17 TWRP 对照一致。metadata feature=0x499。

`FUXIM2 prepare=Unsupported`，selected-pack=2、cp-flags=`0x44`、read-bytes=0。
当前 `F2rPrepare` 要求 `CP_UMOUNT_FLAG`（0x01）；0x44 仅含 compact-summary (0x04)
和 CRC-recovery (0x40)，不含 clean-unmount 位，因此代码在文件目录查找前返回
Unsupported。没有 `lookup`、文件大小或文件 SHA 的实机结果，不能判定非 inline 读取通过。
上次成功的 inline 文件试验为 cp-flags=0x145；本轮 TWRP 之前已 rw 挂载 metadata，
但照片本身不能证明具体状态变化原因或文件系统损坏。不能回退旧 checkpoint 或放宽该保护。

UFS `stop=1`、双 doorbell=0、run=0、HCS=0x10f、IS=0、poisoned=0；最终 pre-USB
park。SMMU configured=1、GFSR=0、FSR=0x400，未证明完整路由恢复。

下一步候选是让 Android 正常启动并通过系统菜单正常关机，再从关机状态进入
fastboot，用同一镜像的独立 attempt-02 检查新 checkpoint 标志。正常 Android 生命周期
可能更新文件和元数据，不能保证旧 TWRP 文件 hash 仍适用；若状态仍不满足或 hash
不同，应保留结果并定位，不能跳过策略。Android 正常关机会尝试卸载文件系统，
但最终 clean checkpoint 必须以实机日志确认。

标志定义见 [Android kernel F2FS 头文件](https://android.googlesource.com/kernel/common/+/refs/tags/android14-5.15.189_r00/include/linux/f2fs_fs.h)，
正常关机卸载逻辑见 [Android init reboot.cpp](https://android.googlesource.com/platform/system/core/+/android16-release/init/reboot.cpp)。
