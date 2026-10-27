# fuxi TWRP A17 静态分析与只读实机对照 — 2026-10-27

## 输入与证据

用户更正：先前 A16 TWRP 在本机 Android 17 上不能解密 `/data`；上传
`TWRP-FUXI-A17.img` 并报告当前在新 TWRP 中成功解密。镜像原件复制到
`D:/Projects/UniXNU/migration/20261027-twrp-a17-static/`，不纳入 Git。
镜像长 104,857,600 字节，SHA256
`56f5f36e9aaeb9e79815c702d9e9196c8c0e1b03d363ec4e4c9646cd4af1444c`。
固定哈希的离线解析器 `tools/audit_fuxi_twrp_a17.py` 产生
[逐文件证据](evidence/fuxi-twrp-a17-interfaces.json)；它只解压/读 ELF，
不执行镜像中的代码。旧审计脚本及旧档案留作历史比较，不再用来代表当前解密参考。

## 镜像结构与新旧差异

Android boot v4：header_size=1584、kernel_size=0、ramdisk_size=76,072,415。
LZ4 legacy 压缩，CPIO 解压后 147,262,572 字节，SHA256
`8e7b2178b92b04d1e8d50ff6e6b51fe48ec14cf8126cf7dd0e508ce378225c25`；
4,025 个条目、318 个 `.ko`。这是 recovery ramdisk，没有内核正文；不能仅凭
镜像头或文件名断言 Android 17 解密能力。

与旧 A16 原件逐条比较：新镜像没有旧镜像的空 `.` 目录条目；所有共同
条目里只有 `prop.default` 内容不同。它把系统、vendor、odm、product 等
`ro.*.build.version.release` 从 16 改为 17，部分 fingerprint 的版本文字从
15 改为 16，日期时间戳相差 1 秒。关键事实同时保留：`ro.build.version.sdk=32`、
`system/bin/recovery` 内版本字符串 `3.7.1_12-_v9.0_A15`、模块 vermagic
`5.15.78`。这些混合字段不能按标签简单视为真实 Android 平台版本。

`system/bin/recovery`、`system/etc/recovery.fstab`、`system/etc/twrp.flags`、
KeyMint 服务与库、所查 `ufs_qcom`/crypto/SCM 模块哈希均与旧镜像相同。
因此本次上传没有新增不同的解密可执行文件。属性变化与这次成功现象相关，
但是否由特定属性决定仍需执行轨迹或受控实验，不能由静态差异单独证明。
现有 fstab 仍声明 `/data` F2FS + `inlinecrypt`、
`fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0`
和 `metadata_encryption=aes-256-xts:wrappedkey_v0`，密钥目录在
`/metadata/vold/metadata_encryption`。符号与模块依赖只说明潜在路径，不是
UEFI 实现或实际 TEE 调用记录。

## 当前手机只读观察

2026-10-27 09:59:41 +08:00，ADB 为 `fcde91e`、`fuxi`、recovery；
`ro.build.version.release=17`，`ro.twrp.version` 仍显示
`3.7.1_12-Xiaomi13_v9.0_A15`。`/metadata` 由 `/dev/block/sda17` 以 F2FS
`rw` 挂载；`/data` 和 `/sdcard` 由 `/dev/block/dm-7` 以 F2FS `rw` 挂载，
`/data/system`、`/data/media/0` 以目录形式可见。结合用户实际解密确认，
这构成该 recovery 下 `/data` 可用的实机证据；未从设备读回运行镜像全文
以独立证明其字节与上传文件完全相同。

仅使用只读 ADB 命令，没有挂载、重挂载、写文件或读取包装密钥内容。
`/metadata/vold/metadata_encryption/key/version` 大小 1 字节、SHA256
`6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b`，
与 M2 UEFI 屏幕一致；metadata 原始首块 4096 字节 SHA256
`e77426cf7e4e7d0c2af46e8c8434a358a6c8f923c7b614ec8a72ec288446e51d`
也与 M1/M2 一致。userdata 原始首块 SHA256 为
`f7480f0ad4b1080c71b3664b0402dbe9c0e8f11d9b6a539d1777139ecc41fbec`，
与上次 UEFI 的 `890d7f62…be33` 不同。两次之间 recovery 已挂载可写卷；
仅凭该差异无法判断原因、损坏或解密正确性。原始块只在主机内存中哈希，
没有保存其内容。证据 JSON 在交付目录 `twrp-reference.json`。

现有非秘密下一候选：`/metadata/aconfig/maps/system.package.map`，
10,527 字节，TWRP SHA256
`14f3d8675423917e383a71c936f4d9a81a29480f34ae3c550e0f4c34e53a0991`。
它超出单个 4 KiB 块，适合 M2 非 inline 内容读取验证；下一轮 UEFI
需明确目标和新的候选镜像，不能把本轮 1 字节 inline 成功当成这条路径已通过。

## 边界

M2 的 1 字节文件及首块哈希取得独立 TWRP 对照，但这不验证设备上的
非 inline 数据块、非空 NAT journal 或 UEFI 的 Android 密钥解封。
TWRP 能解密 Android 17 不能自动转移为 UEFI 已能解密。后续 M3 必须
单独验证 SCM/QSEE、硬件包装密钥、ICE 与 fscrypt 的确切组合。
