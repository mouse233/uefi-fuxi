# M3 standard INFO 调用上下文诊断 — 2026-10-28

## 触发事实

C2 legacy 72000600 与 object 72000602 两次 root register 均返回
`a0=FFFFFFFF80000001 a1=a2=a3=0`，OO 仍为 0。两次均按策略保留页和桥，
没有继续 release/delete/free，没有 TA、密钥或解密。准确 raw 错误含义尚未查明。
换命令入口没有解决失败；不能由 a1/a2 零或 availability=1 推断对象调用完成。

## 本候选的最小取证

只观察普通世界的 `CurrentEL` 与 `DAIF`，不写寄存器、不切换异常级、不启用中断。
此前入口处 fast SMC64 INFO 自查询 C2000601 成功时，在既有 M2/UFS 停队列后，
发起一次 standard SMC64 INFO 自查询 `x0=42000601 x1=1 x2=02000601`。
它复用生产 FdpMakeAvailabilityQuery 的 INFO 字段，只清除 call-type bit31；
无缓冲指针、无桥、无对象、无 blob/TA/key。任何返回都不重试，也不追加 invoke。
同步 SMC 仍无硬超时。

fast 对照来自同次启动的入口日志；standard 查询在 UFS 停队列后执行，二者不是同一
时刻的连续调用。这限制了因果推断。standard INFO 形式本身是否被该固件接受未知：
若同样失败，只说明此控制也失败，不能直接证明所有 standard SMC 都不可用或错误已归因。
若成功，也只证明该 INFO 控制路径成功，不能证明 owner32 的对象调用或桥访问成立。

## 实现与绑定

默认关闭 FUXI_M3_SMC_CONTEXT；要求 parked root diagnostic 的构建配置，
但编译排除 M3SmciDiagnostic.inc 的 root/register/release 实现。
交付清单将真实操作明确记为 `standard-info-control`，bridge_ops=[]、bridge_bytes=0；
镜像检查同时要求 CTX 标记存在，bridge-create 与对象调用标记不存在。
保留显式开关而不改变之前已验收候选的文件/镜像。

CurrentEL/DAIF 用 AArch64 只读 MRS 指令取得，编译进真实交付 EFI。
5 个 ASan/UBSan 主机向量验证生产探针：fast gate 为 false 时无调用；成功、不可用、
interrupted 与实测 raw 错误形态均至多调用一次，参数只有 INFO 标量，不分配资源。
主机测试用合成 EL/DAIF 参数，不模拟真实异常级行为。
15 项完整交付检查全部退出 0（含现有桥构建器、56 项 root 生命周期回归、CTX 生产测试、
SMMU/route/receiver、USB state、M0/M1/M2/f2fs-tools、报告缓存及交付镜像绑定）。

这是一份进一步定位用诊断交付，**C2 仍未通过**，不能视为 root/TA/解密修复。
硬件结果 pending，需独立 attempt 和照片核对 CTX、UFS/SMMU、PARK。
