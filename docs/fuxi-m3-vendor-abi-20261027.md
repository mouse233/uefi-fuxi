# M3：A17 厂商 SCM/HWKM 静态 ABI 线索（2026-10-27）

范围是已归档的 TWRP A17 ramdisk，静态反汇编，不运行 TA/SMC，不读取密钥。
`qcom-scm.ko` SHA256 `8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5`；
`crypto-qti-hwkm.ko` SHA256 `be67c86de45b02bfc9e00089c6b49899c1d2579e7db2860e684b186cf22e866d`。
两个模块属于用户提供的 ramdisk；证据是文件内容而非 UEFI 时运行状态。

## 设备模块中的调用

- `qcom_scm_config_set_ice_key` @0x5518 将 descriptor 头设为 service=0x10、
  command=0x05，参数信息为 0x86，保存来自 w0、x1、x2、w3、w4、w5 的六个
  参数，然后调用 `__scm_smc_call`。`qcom_scm_clear_ice_key` @0x5610 的
  service/command 为 0x10/0x06、参数信息为 0x02，保存两个参数；
  `qcom_scm_derive_raw_secret` @0x56fc 的 service/command 为 0x10/0x07、
  参数信息为 0x224，保存四个参数。这些是静态反汇编对 descriptor 的观察；
  暂不推断所有参数类型、权限或能否由 UEFI 使用。
- `crypto_qti_program_key` @0x23c 先调用 `qti_hwkm_init`；在该静态路径中，
  清配置、调用 `qtee_shmbridge_allocate_shm`、复制并 flush 后，以逻辑 slot
  乘 2 作为第一个参数调用 `qcom_scm_config_set_ice_key`；成功后再写配置并
  invalidate/free shared memory。清除路径 @0x4d8 亦将 slot 乘 2。条件分支和
  设备初始化决定是否到达这些调用；这不是已验证的 UEFI 操作顺序。
- `__scm_smc_call` @0x85b4 对参数数量至少为 5 的 descriptor 进入额外参数
  缓冲区处理，并可通过 `qtee_shmbridge_allocate_shm` 分配共享区域。单个 INFO
  availability 查询的参数数为 1，不能据此省略未来六参数 ICE 调用的共享内存、
  地址、缓存和安全域约束。SMC 指令本身不提供硬超时。

上游通用实现仅作概念参照，其 set-key 包装是五参数：
https://android.googlesource.com/kernel/common/+/refs/tags/android13-5.15-2024-07_r1/drivers/firmware/qcom_scm.c
因此不能直接复制该参数布局到本机。需要对照匹配设备的头文件/调用点、验证
长参数与共享缓冲协议、安全域权限、ICE 时钟/HWKM 初始化、配置写与清理；
实机验证前禁止把上游示例当作本机已确认 ABI。成功查询 availability 也不证明
后续装钥可用。现有 `FdpMakeAvailabilityQuery` 是默认关闭且未实机执行的 INFO
查询草稿，不包含 set/clear/derive 调用。

## 实机发现与边界

attempt-01 照片中的 `SCM=Not Found` 和 `QSEE=Not Found` 只说明现有 UEFI
DXE 调度点没有发现这两个协议；独立原始 SMC/QTEE 路径仍待验证。M1 UFS 只读与
停队列成功，M2 checkpoint=0x44，因 clean-unmount 位缺失按策略拒绝读文件。
没有执行 SMC、安装密钥或解密，也没有证明 SMMU 完整恢复。

复现：在实验 UEFI 仓库运行 `llvm-objdump -dr --disassemble-symbols=` 指定上述
函数和对应 `.ko`，并先核对两文件 SHA；不要把反汇编中的错误日志分支用于
实机导出密钥或包装密钥。上述参数解释为静态推断，最终以匹配源码和实机验证为准。
