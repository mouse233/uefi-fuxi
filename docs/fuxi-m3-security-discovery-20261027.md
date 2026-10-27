# M3 DXE 安全协议发现 — 2026-10-27

本轮在 `FuxiNativeUfsDxe` DXE 入口增加两次 `LocateProtocol`，分别查询
`gQcomScmProtocolGuid` 与 `gQcomQseecomProtocolGuid`，通过现有 UFS 缓存报告
记录 EFI_STATUS 及接口指针是否非空。探针不调用协议方法、不执行 SMC、不加载 TA，
不读取或传出 key/blob；不实现任何解密。既有 M1/M2 读和停队列流程不变。

现有 M0 `FuxiDataProbeDxe` 的安全发现位于 ReadyToBoot，而 M2 停驻候选在此之前
停住，并且构建配置 `FUXI_DATA_PORT_PROBE=0`；此前构建通过不代表探针上过机。
这次将查询放在实际 M2 UFS 驱动 DXE 入口，确保可以通过缓存报告看到结果。

这是该 DXE 时点的 UEFI 协议发现，不证明协议函数可执行、参数 ABI 正确、TEE
服务存在、密钥可使用或 UEFI 可解密。NOT_FOUND 也不证明之后不存在 provider，
更不证明底层安全监控不可访问。现有仓库声明了协议，但尚未证明本配置装载了
提供者。安全发现结果与 M2 文件读取、控制器状态分别解释。

Android 公共源码中的 SCM 和 UFS crypto 路径可用于梳理参数、capability 与 keyslot：
https://android.googlesource.com/kernel/common/+/refs/tags/android13-5.15-2024-07_r1/drivers/firmware/qcom_scm.c
https://android.googlesource.com/kernel/common/+/c107785c7e8dbabd1c18301a1c362544b5786282/drivers/ufs/core/ufshcd-crypto.c
公共源码不能代替 fuxi 厂商 ABI 与实机验证。尤其不要直接将上述 SCM set-key
参数当作本机已验证接口；HCE、ICE 初始化、缓存、HWKM slot 编号和安全固件
权限均待核实。独立的 INFO 查询草稿仍默认关闭，也不包含在本交付镜像中。

候选 `out/m3-protocol-discovery-v1`：镜像 SHA256
`6cb8015b5d52ecbc47dd2b2d9138b991ad5078d61554bf978803fb2b4bebb948`。
12 项主机检查通过；`tools/check_fuxi_m3_discovery_image.py` 检查交付镜像和 EFI
绑定、两种协议 GUID、两条诊断字符串，以及已有交付反汇编报告中的零 SMC。
完整结果与未上机边界以候选 REVIEW.md 为准。
