# M3 C2 最小 root register/release — 2026-10-28

## 范围与本机静态绑定

本候选只调用 QTEE root 的 registerWithCredentials（null 输入对象），验证返回远端
client-env 对象，随后 release，再 delete 桥。没有加载 app-loader/KeyMint TA，
没有读取 blob、安装密钥或解密。改动层为 UEFI DXE 和构建/检查工具。

本机固定哈希 qcom-scm.ko 的 `qcom_scm_invoke_smc_legacy` @0x7148：svc=6、
cmd=0、owner=0x32、arginfo=0x224，四个参数为 in_phys/in_bytes/out_phys/out_bytes，
传给 `__scm_smc_call` 的 type=2。后者 @0x8654..0x8664 令 bit30=SMC64、
bit31=(type==1)，故本候选使用 **0x72000600**，不是 INFO/桥的 fast call 形式。
@0x8948..0x8954 复制 a1..a3 到 res；包装函数把 res[0] 作为 response_type、
low32(res[1]) 作为对象 result、low32(res[2]) 作为 data。

固定哈希 smcinvoke_dlkm.ko 对照 root register 的 op=5/counts=0x1100，
release @0x7c6c 的 op=0xffff、输入输出各 4096。`audit_fuxi_m3_smci_root.py`
固定两模块 SHA、上述特定指令并保存反汇编；原始输入和两次篡改拒绝通过。
这些是局部二进制事实，不能替代完整驱动/运行态权限和固件等价证明。

## 行为与保留策略

默认关闭 FUXI_M3_SMCI_ROOT，要求 bridge call、invoke availability、诊断驻留。
与 metadata-key/bridge-blob 互斥。先运行既有 M2 与 UFS 停队列，再在 INFO legacy
invoke availability=1 且 UFS 未 poisoned 时分配低于 4 GiB 的连续 8 KiB。
enable/create 注册整段，前后各 4 KiB 为输入/输出缓冲。

1. 输入 LE32 `[1,5,0x1100]`，单个 null 输入对象和输出对象占位均清零。
2. flush → standard SMC64 → invalidate，打印 a0..a3 和消息头/对象描述符。
3. 仅接受 a0/a1/a2/a3 全零、请求头未变、输入对象/保留位/尾部未变、输出页全零、
   输出 handle 为 >1 且 local-object 位未设置的子集；输出 handle 来自输入页 +20。
4. 对该 handle 构造 `[handle,0xffff,0]`，重新 invoke，验证相同严格终态、无输出对象
   或非零 piggyback；对象 release 成功后才擦净页面并 delete 桥；delete a0=0 才 free。
5. create 未知完成、invoke 非零/中断/回调/listener/损坏消息、release/delete 失败均保留
   相应页/句柄并驻留，不重试、不猜 resume、不执行 callback 或 listener，不继续加载 TA。
   invoke 之后未知状态不擦写页，防止安全世界仍持有缓冲。

这是用于定位和最小闭环的严格接受子集，**没有通用回调/中断/对象管理器**。非空输出页
可能是合法 piggyback；拒绝该页只表示本候选不能处理，不能宣称固件 ABI 错误。
同步 SMC 无硬超时；屏幕停在 begin 时需要保留画面并手动重启。

## 验证与实机边界

27 个 ASan/UBSan 生产代码生命周期向量覆盖成功、页分配、enable/create/delete、
SMC interruption/wait/error、response_type、对象结果/data、null/root/local handle、
描述符保留位、输入头/尾、输出页/piggyback 与 release 失败；未知态不执行后续调用且不 free。
C1 共用桥代码回归通过。14 项完整交付检查全部退出 0；交付 EFI smc 指令 1 条，
两个对照模块为 0；固定模块审计另行通过。镜像 SHA、55 个源码文件绑定与 attempt
记录见 out/m3-smci-root-v1/REVIEW.md。主机结果不代表 QTEE 实机通过。
