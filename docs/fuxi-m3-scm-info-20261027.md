# M3 SMC64 INFO 自查询候选（2026-10-27）

此前实机 DXE 中 SCM/QSEE UEFI 协议均未发现，不能证明底层安全监控不可用。
本候选新增默认关闭 `FUXI_M3_SCM_INFO`，只在独立诊断镜像中开启：通过
现有经过主机测试的 `FdpMakeAvailabilityQuery` 生成一次 SMC64
INFO/IS_CALL_AVAILABLE 自查询：x0=0xc2000601、x1=1、x2=0x02000601，
其他参数为零。该候选不查询 ICE set/clear/derive，不处理 key 或共享缓冲。

调用前打印 begin，返回后打印 a0/a1、解码状态、availability；a0 非零或 a1
不为 0/1 时保持不确定，不降级或重试。一次同步 SMC 没有软件硬超时：若未
返回，可能停在 begin 行，M2 停驻候选在进入诊断前已禁用 UEFI watchdog，
不得假定会自动恢复。上机需用户可见设备并保留手动重启条件。此项有真实
实机风险，主机测试和反汇编不能证明调用安全或保证返回。

查询成功只能说明该次 INFO 自查询返回，不证明 ICE/KeyMint/QSEE、密钥加载或
解密可用。NOT_FOUND 的 UEFI 协议与 SMC 是不同层；不绕过 TEE 策略。
现有原始 UFS 只读诊断、checkpoint 拒绝策略和停队列流程沿用。

候选 `out/m3-scm-info-v1`，镜像 SHA256
`d23874d80d1ce8c1a60b69568a7b1252b4053e7e5af9c0a21846fd0979a544dd`。
12 项主机检查通过；UFS 交付模块有 1 条直接 SMC，对照模块均为 0 条，
构造/解码已有主机测试，详情见候选 REVIEW。实际硬件结果 pending。
