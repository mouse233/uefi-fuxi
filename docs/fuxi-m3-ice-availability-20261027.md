# M3 ICE SCM 服务可用性查询候选（2026-10-27）

前一实机照片中 SMC64 INFO 自查询 a0=0、a1=1，正常返回；UEFI SCM/QSEE
协议未发现。新候选在相同 INFO 自查询返回 available=1 后，顺序用相同 SMC64
INFO 命令查询 subject 0x02001005、0x02001006、0x02001007（厂商模块中
对应 ICE set、clear、derive 的 service/command）。每次只询问 availability，
没有直接执行 subject、装钥、读取 blob 或调用 TA。自查询失败/不可用时不查询
subjects，任一 subject 返回异常时停止后续调用；返回 unavailable 本身不是错误。

最多四次同步 SMC，均无法通过软件硬超时保证返回；若停在某条 begin，
保留照片，必要时用户手动重启，不将不返回解释为 unavailable。即使某服务
报告可用，也不证明调用权限、设备 ABI、密钥操作或解密成功。

构建开关默认关闭，仅在独立候选启用。候选 out/m3-scm-ice-avail-v1，镜像
SHA256 `06911cdf369d5f87fd167a234b66800ac31d241db6e5f80677bf81dfb6c79361`。
12 项主机检查、两种对照模块构建通过；交付 UFS EFI 1 条 SMC 指令（多次调用
同一入口），对照模块均 0 条。实际安全监控服务结果待实机验证。
