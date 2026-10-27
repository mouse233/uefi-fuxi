# M3 TWRP metadata 明文基准与 DM 几何 — 2026-10-27

## 实机只读结果

fcde91e/fuxi，A17 TWRP、`ro.build.version.release=17`；`/data` 以 F2FS rw 挂载于
`/dev/block/dm-7`，dm 名称 `userdata`，直接下层 `sda32`，设备号 259:16。
`/metadata` 仍为 F2FS rw。没有挂载/重挂载或分区写入。

| 首个 4096 字节 | SHA256 | 偏移1024处 F2FS 魔数 |
| --- | --- | --- |
| 已解密映射 `/dev/block/dm-7` | `d99375331359c5120ef2dc6a6019ff5ab3b0a55063f38facd7e35d3be305257b` | 是 |
| 原始 `/dev/block/by-name/userdata` | `e815d5f476ef20b73c152bf6640a7881d7912f9dceeaea95700f10d9904d3d5a` | 否 |

程序只在主机内存中计算 SHA/魔数，没有保存块内容。TWRP 已挂载可写卷，
这些是同一次 recovery 会话的不同时间观察，不是冻结快照。

sysfs：`dm-7` 与 `sda32` 均 469,917,144 个 512 字节扇区，userdata 起点
24,887,808 个 512 字节扇区，逻辑块 4096 字节；起点和长度分别与先前 UEFI GPT
`0x2f7840..0x3afc3fa` 一致。`DM_TABLE_STATUS` 的安全白名单结果：

```text
target=default-key  cipher=aes-xts-plain64  key_field=- (已脱敏)
target_begin=0  target_length=469917144  device_start=0  iv_offset=0  # 512-byte sectors
backing=259:16  sector_size=4096  iv_large_sectors=1  wrappedkey_v0=1
```

映射类型、设备号与 sysfs 直接下层相符。此结果是当前 TWRP 会话的只读快照，
不能推断 UEFI 中安全固件的密钥可用性或跨重启保留状态。

## 查询与测试绑定

TWRP 没有 `dmctl`/`dmsetup`，因此编译静态 AArch64 只读工具 `tools/m3_dm_status.c`，
临时放在已确认的 `/tmp` tmpfs。它仅对固定 `userdata` 执行 `DM_TABLE_STATUS`，
要求目标类型与参数格式匹配且 key 字段为 `-`，只输出固定字段；未知/未脱敏时
拒绝输出。禁用 core dump，查询缓冲区在退出前清零。设备返回的 key 字段为 `-`，
没有把原始表字符串或密钥传回或存储；临时程序已从 tmpfs 清理。

初版只读查询的返回 `next` 包含对齐填充，较 `data_size` 多2字节，严格判断
返回 bounds 错误；按 Android libdm 截断至 data_size 并增加测试后成功查询。
最终设备程序 SHA256 `110771ceec7ac746d9b763ebbc32562c1ef3d191d177b4b5bcc80104fb2b86ba`，精确源路径重建哈希一致。
工具源码与实测几何测试绑定提交 `c1fd1efed371d2172ecbde24ceb47640bcf58c11`；ASan/UBSan 测试通过。

按实际映射参数和既有 GPT 几何，规划器主机测试得到映射首块 disk LBA
`0x2f7840`、DUN 0，末块 disk LBA `0x3afc3fa`、DUN 58739642；越界请求拒绝。
这验证地址计算，不执行密钥装载或设备解密。测试与源码绑定见 `source-binding.json`。

## 未完成

UEFI 尚无经实机验证的 KeyMint/QSEE/SCM 密钥封装处理、ICE keyslot 安装与清理、
带加密上下文的 UFS 读取，也没有对应的明文 SHA 对照。现有安全调用仅有默认关闭、
未在设备执行的 INFO 查询草稿；不可从 TWRP 成功或 dm 表推出 UEFI 有权限使用密钥。
下一步需对照具体厂商模块和固件 ABI，设计受限的状态探测和 UFS crypto 请求/错误处理，
之后才能尝试与上述明文摘要比较。
