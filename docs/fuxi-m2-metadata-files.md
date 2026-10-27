# M2 metadata files v1 — 2026-10-26

当前主线：`feat/twrp-data-uefi`。改动层为 UEFI 的只读 F2FS 核心、原生 UFS
诊断入口、构建与交付检查；未修改 DarwinBoot/XNU、Android 分区或系统载荷。

## 当前交付与边界

- 候选：`out/m2-metadata-files-v1`。
- 交付镜像：`Mu-fuxi-m2-metadata.img`，1875968 字节。
- SHA256：`cf28d6375ae7a321334fa789ef996a7f7a8e72df2a806bde9d5e9453160cf009`。
- `Mu-fuxi-ufs-m1.img` / `Mu-fuxi-usb-ram.img` 是供既有校验器使用的同字节别名；
  此候选实际执行的是 M2 前置诊断，不提供 USB 接收窗口。
- 框架固定 `7e237de0aa81a8f38221134c752af2d71236cddc`；设备 board.toml 固定
  `1d071dae4618b0676d313cfbe1fc39689e6f139e`，不修改共享的 schema-2 配置。
- 完整 DEBUG AARCH64 平台与 no-SMC/query 两种独立模块均构建成功，M2/park 宏均启用。
- 十二项主机/交付检查全部真实退出 0，详见 `check-exit-codes.json`。
- 最终全平台构建监测 D 盘余量最低 45.10 GiB，保留下限 12 GiB。
- **未上机；没有 `/metadata` 实机文件读取或 Android 解密成功结论。**

## 读取实现

沿用独立 Read 回调，无分配、MMIO、SMC、写入或 Linux 运行时依赖：

1. 双 superblock 和 CP 首尾 CRC/版本校验；按最新有效 CP 选择，不因传输错误
   或最新 CP 为 dirty/unsupported 而退到旧 clean CP。
2. clean CP 的普通/compact NAT journal 覆盖；检查条目数、重复 NID、NID/地址范围，
   journal tombstone 不回落到旧 NAT 表。标准 NAT bitmap 选择对应表副本。
3. NAT owner、node footer NID/owner/offset 校验；额外 inode 属性与默认 inline xattr
   调整地址布局。目录/普通文件分别处理，拒绝 symlink、加密、verity、压缩和 casefold。
4. inline/block 目录、绝对路径查找；目录最多 256 个块、路径 1024 字节/16 层，
   拒绝 dot 组件、错误续槽、目标重复名及 dentry/inode 类型不符。
5. inline、直接、间接和双重间接文件映射，稀疏洞返回零；无效/未分配地址报错。
   中途 I/O/格式错误清空本次输出并返回 ReadBytes=0，不暴露部分读取为成功。

SB feature `0x499` 只说明能力集合，不表示每个 inode 加密。按 inode 单独拒绝
未实现策略；未实现 inode checksum 特性、多设备、cp_payload、大 NAT bitmap、
dirty CP/roll-forward、Android dm-default-key/fscrypt/ICE/QSEE、BlockIo 与 RAM 对象发布。
这是 clean/offline 只读解析，不是可并发访问 Android 正在写入卷的完整文件系统。

## 候选实机行为

先保留 M1 的 GPT、metadata/userdata 原始首块与三次独立读取，再执行 M2：

- 打印 CP 选择/flags、feature、journal 数；无法准备时到此停止。
- 打开 metadata 根目录，最多打印 16 项，长度/非打印字符明确裁剪，不打印文件内容。
- 尝试 `/vold/metadata_encryption/key/version`，只处理普通文件，最多 1 MiB。
  这是非秘密版本文件的约定路径，尚未确认本机存在；缺失应返回 `Not Found`，
  不更换目标、不伪造成功。只有完整读取后打印字节数及 SHA256。
- UFS shutdown 沿用 M1 的双 doorbell/run/fatal 检查；不确定时保留 DMA，后续不再触碰 UFS 寄存器。
- 在 APRIORI 中驻留于原生 UFS 驱动，**不返回到 UsbfnDwc3Dxe/FuxiUsbRamDxe 调度**。
  入口关闭 UEFI watchdog；最终打印 `FUXIM2 PARK: no USB receiver; no handoff`。
  驻留不是 CPU/USB `HALTED` 或完整 SMMU 路由回滚，不是进入 Android/XNU。
- 报告容量从 48 增至 96 行，保留 dropped/truncated 警告。屏幕缓存重放不增加读取次数。

## 主机验证

- 14 组引导解析 fixture，及原始重复读取边界/错误处理测试。
- 38 组独立编码文件样本，覆盖 journal 覆盖/tombstone/畸形条目、两种目录、
  inline 文件、全部节点层级、稀疏文件、跨块/非对齐读取、策略拒绝和 I/O 失败清零。
- 独立 Ubuntu f2fs-tools 1.16.0-1 生成并填充 feature=0x499 的 128 MiB 常规文件镜像，
  **未挂载、未打开块设备**。生产代码逐字节比对完整 8193 字节文件、18 字节小文件、
  5 MiB 文件的远端跨块读取。工具包 SHA256
  `914097c27d98f03e5fe56c5038e1a5abd81b8cbf0b24132fa234d608dfa60ea3`。
- 上述 C 测试用 ASan/UBSan；原 M0 82 组、UFS 核心/SHA 向量、USB EP0 22 项×4 配置、
  9 项 stop、报告缓存、规范 SMMU/route/receiver/image 检查均通过。
- 交付 FD 中实际包含本次 UFS EFI；M2/park 字符串及 APRIORI 顺序、源码和镜像绑定通过。
  交付及两个独立原生 UFS EFI 的 SMC 指令均为 0。

## 构建与检查复现

在容器 `unixnu-fuxi-build-arm64` 中，工作目录 `/work/ramdisk-test/uefi-twrp-data`：

```sh
/opt/fuxi-venv/bin/python3 tools/build_fuxi_ufs_candidate.py \
  --base /work/migration/20261026-upstream/unixnu-ram \
  --device /work/ramdisk-test/UniXNU-fuxi \
  --device-config-ref 1d071dae4618b0676d313cfbe1fc39689e6f139e \
  --edk2 /work/uefi-fuxi/Mu_Basecore --output out/m2-metadata-files-v1 \
  --m2-metadata-files --usb-ep0-trace 1
```

两种独立模块用 `tools/build_fuxi_data_port.py --m2-metadata-files`，query 版另外
加 `--scm-query`，输出到候选 `modules-no-smc` / `modules-scm-query`；顺序构建。
在 WSL 中执行十二项检查：

```sh
python3 tools/qualify_fuxi_ufs_candidate.py \
  --device ../UniXNU-fuxi --edk2 ../../uefi-fuxi/Mu_Basecore \
  --output out/m2-metadata-files-v1 \
  --f2fs-tools out/m2-metadata-files-v1/host-tools/extracted/sbin
```

f2fs-tools 仅下载 Ubuntu 包并解包在本候选 out 中，未做系统安装。`--f2fs-tools`
也可指向已验证的 mkfs.f2fs/sload.f2fs 目录；测试只在独立临时目录创建常规文件。

## 下一次上机与验收

本轮未操作手机。上次 v8 USB halt 失败后的驻留状态不能被当成 fastboot/Android。
用户准备好一次新的 fastboot 后，先核查互斥任务，再验证 fcde91e/product=fuxi/unlocked、
usb-ram boot profile 和上述 SHA256。建立独立 attempt-01，将精确镜像与
verification.json 放入其中，用既有 Windows single-boot adapter 临时启动；只 boot，
不 flash、不擦除、不改槽。本候选不发载荷，也不期待 Windows USB 枚举。

照片应包含 prepare/CP flags、root-list、lookup、file-size/full SHA、UFS stop 和最终 park。
`prepare=Unsupported` 要按 flags/格式定位，不能跳过 clean CP 或 inode 策略。
根目录列表或文件 hash 出现不等于整个 M2 完成；只有与 TWRP 的同状态独立对照一致
后才记录真实文件读取验收通过。参考 `TWRP-REFERENCE.md`，本轮对照尚未采集。

既有 M1 v8 与 attempt-01 的镜像和源码绑定仍保留在原目录，未覆盖或重新验收。

公开格式依据：Linux v5.15 `include/linux/f2fs_fs.h`、`fs/f2fs/segment.c`、
`fs/f2fs/f2fs.h`；仅使用磁盘格式事实，未复制 Linux 文件系统实现或链接其源码。

附加默认关闭回归：未启用 M2/park 的独立模块也已编译退出0，原生UFS EFI无M2 park标记、0条SMC；默认开关保持关闭。


## attempt-01 实机结果 — 2026-10-26

2026-10-26T22:49:51.566129+08:00 单次临时启动 Sending/Booting OKAY，退出0。IMG_7071 原图与哈希、
启动记录、结构化判读见 attempt-01/REPORT.md、assessment.json、device-test.json。
prepare/root-open/root-list/lookup/file-read 均 Success；CP pack2、flags145、version5788ea72、
journal0。根目录13项（含点项），/vold/metadata_encryption/key/version 为 nid69、
1字节 inline 文件，SHA256 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b。UFS stop=1、双doorbell=0、run=0、
poisoned=0，最终明确 pre-USB park，无USB接收器/交接。
首个inline文件实机读取已观察到；未新增TWRP独立对照、非inline文件数据读取、
非空NAT journal覆盖、Android解密、大文件/RAM对象或XNU交接通过结论。
此结果补充上文构建时的“未上机”状态，不改写原构建/绑定记录。

## 2026-10-27：TWRP 对照补充

用户提供并进入 A17 TWRP，`/data` 经 dm-7 挂载。只读 ADB 验证
`/metadata/vold/metadata_encryption/key/version` 大小/完整 SHA256 及
metadata 首块哈希均与本候选实机结果一致。当前确认的是 inline 文件
独立对照；非 inline 文件数据块与非空 NAT journal 尚未实机验证。
候选目标与镜像 SHA/源码绑定不变。详见
[A17 TWRP 报告](fuxi-twrp-a17-static-20261027.md)。
