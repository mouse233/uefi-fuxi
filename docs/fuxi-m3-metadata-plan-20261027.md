# M3 metadata 映射规划器 v1 — 2026-10-27

## 当前结果

UEFI/TWRP 分支源码提交 `44ea501733d9cbcec1bdeac528efe5ff13e252d8`。本阶段是主机和 AARCH64 模块编译，
不是设备解密候选，没有生成可启动镜像，也没有运行手机或安全调用。
M2 的非 inline 文件对照已通过；非空 NAT journal 和完整 SMMU 恢复仍未实机覆盖。

新增 `M3DefaultKeyPlan.c/.h`：只对调用方明确提供并核验的单一 dm-default-key
目标、4 KiB UFS 块/加密单元、AES-256-XTS、wrappedkey_v0 和 iv_large_sectors
计算 metadata 读取计划。所有 dm 扇区字段以 512 字节为单位，区分：

```text
relative = logical_sector - target_begin
physical_lba = userdata_partition_first_lba + (device_start + relative) / 8
first_dun = (iv_offset + relative) / 8
```

完整映射与请求都要对齐且落在 userdata 分区内；零长度、溢出、越界和未知配置
拒绝，失败时清零输出。底层设备起点不混入 DUN。接口只计划文件系统元数据，
不能用于覆盖 dm-default-key 的 fscrypt 文件数据。`MappingVerified` 由未来调用方
负责证据和设备身份绑定，本阶段没有实际映射获取器，不能自行置真。
该代码不读取块、不使用密钥、不调用 SCM/ICE、不提供明文或运行时解密。

`tools/collect_fuxi_m3_reference.py` 是待运行的只读 TWRP 基准采集器：确认
fcde91e/fuxi、recovery/release17、现有 `/data` 和 `/metadata` 挂载；分别读取
映射 `/data` 和原始 userdata 的首个 4096 字节，仅记录 SHA256 和 F2FS 魔数。
同时记录 dm 名称、直接下层设备和挂载选项；它**不读取 device-mapper 表或密钥**，
不保存块内容，不自动挂载或改变手机状态。`table_geometry_verified=false`，
因而该采集器不会为规划器证明实际 DUN、offset、算法或 keyslot。

## 验证

- 真实 C 规划函数经 clang ASan/UBSan 的成功、边界、越界、未确认配置与溢出测试通过。
- 参考采集器的4项模拟设备测试通过，包括错误设备、未挂载与短读拒绝。
- 默认 no-SMC 和 SCM-query 两种独立 AARCH64 模块构建退出0；编译对象包含
  `FdmPlanMetadataRead`，函数尚未接入运行时读取路径，链接器可剔除未使用代码。
- 反汇编：默认 DataProbe/NativeUfs 均0条 SMC；query DataProbe 1条、NativeUfs 0条。
  这只是编译期指令检查，没有实机调用。详情见 `host-tests.json`、`verification.json`
  和 `source-binding.json`；构建源码与提交逐项绑定。

## 下一步

手机目前预计在 M2 诊断驻留。需要用户自行进入 A17 TWRP 并解密 `/data` 后，
先重新核查设备互斥与身份，再调用采集器获取逻辑首块与原始首块的哈希/魔数。
正常 TWRP 可能 rw 挂载 metadata，后续UEFI文件系统读取仍需 clean checkpoint。
当前首次 TWRP 参考命令（从检出根目录，设备确认后由工作者执行）：

```sh
python3 tools/collect_fuxi_m3_reference.py \
  --adb /mnt/c/Users/zxc92/AppData/Local/Android/Sdk/platform-tools/adb.exe \
  --output out/m3-metadata-plan-v1/twrp-reference-01.json
```

随后还需安全核实真实 dm-default-key 的 target start/length、底层 start、IV offset、
sector size/iv_large_sectors、wrappedkey、设备拓扑和一致性；不得从 fstab、示例或
单个首块 hash 推断它们。再分析匹配固件的 KeyMint/QSEE/SCM/ICE ABI、权限、
错误处理、DMA 与 keyslot 清理，最后才做受限明文对照。现有 INFO 查询开关在
该设备尚未执行过；availability 不证明装钥成功，也不能保证 SMC 硬超时。

地址语义参考 [Android 5.15 dm-default-key](https://android.googlesource.com/kernel/common/+/refs/tags/android14-5.15-2024-06_r9/drivers/md/dm-default-key.c)，
硬件密钥语义参考 [AOSP 硬件包装密钥](https://source.android.com/docs/security/features/encryption/hw-wrapped-keys)。
仅按公开接口事实独立实现，未复制 Linux 或厂商代码。

## 2026-10-27：TWRP 明文参考与脱敏 DM 几何

已在 A17 TWRP 中取得映射 data 首块 SHA/F2FS 魔数及原始 userdata 首块 SHA，
并使用临时 tmpfs 只读程序获取已脱敏的实际 default-key 几何。dm 与 userdata
设备号、sysfs 大小/起点和之前 UEFI GPT 一致；当前 target begin、底层 start、
IV offset 均0，crypto sector 4096、iv_large_sectors、wrappedkey_v0。
依据这组快照增加首末块/越界主机测试；没有 UEFI 解密或 keyslot 实机结果。
详见 [实机参考和验证](fuxi-m3-twrp-reference-20261027.md)。
