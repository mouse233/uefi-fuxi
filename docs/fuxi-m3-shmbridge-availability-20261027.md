# M3 QTEE 共享内存桥可用性查询

TWRP `qcom-scm.ko` SHA256 `8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5`：
`qcom_scm_enable_shm_bridge` @0x437c..0x43a0、`qcom_scm_delete_shm_bridge`
@0x4484..0x44a8、`qcom_scm_create_shm_bridge` @0x457c..0x45b0 组装的
descriptor 分别是 service 0x0c、command 0x1c/0x1d/0x1e，owner 2，参数数
0/1/4。源码参照：[Linux qcom-scm SHM bridge 实现提案](https://lists.infradead.org/pipermail/linux-arm-kernel/2023-August/862942.html)，
以及[高通 QTEE 共享内存桥实现](https://android.googlesource.com/kernel/msm/+/cd6044d4b6c279f7313a471905cd5e5c9b674896/drivers/soc/qcom/qtee_shmbridge.c)。
设备模块有 `qtee_shmbridge_allocate_shm`、register、deregister 等符号；
这仅是 TWRP Linux 内的静态事实，不证明 UEFI 已有可用桥或相同版本 ABI。

候选只执行 INFO/IS_CALL_AVAILABLE 自查询，成功可用后查询 subjects
02000c1c、02000c1e、02000c1d。查询属于 INFO，不执行 enable/create/delete；
无地址、内存分配授权、密钥或加密 I/O。任一异常结果终止后续查询；同步
SMC 无硬超时，可能卡住，需用户在场并保留当时屏幕。available=1 不能证明
桥已启用、创建权限、虚拟机权限、缓存同步、回收或 QTEE 对象调用可用。
候选同时保留已验证的只读 UFS crypto capability 和 M2 路径，停在 USB 前。
