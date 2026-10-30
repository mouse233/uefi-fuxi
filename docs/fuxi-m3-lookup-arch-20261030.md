# M3：匹配当前 TZ 的 lookup-only 候选

2026-10-30，B线 `feat/twrp-data-uefi`，改动层为 UEFI 与主机资格检查。
独立候选 `out/m3-lookup-arch-v1`。它用于验证当前部署契约能否返回已有 TA
对象，不加载 TA，也不调用 KeyMint 方法。M3/M4/M5 及免 USB 重传仍未通过。

## 固定契约与调用范围

[部署审计](fuxi-m3-deployed-loader-20261030.md)已经确认当前 slot A 对应 TZ 的
UID122/op2 接口需要 `0x1011`（BI1/BO1/OO1），架构输出恰为四字节。证据固定为
`evidence/fuxi-m3-deployed-loader-20261030.json`，SHA256
`8c50771e55596540eeb60e3b1589656aa1a5af570f4bfbf7d55f49696e7a5018`。
构建器与交付检查都核对该 pin；这是已采集分区身份与离线接口证据，不能证明
下一次启动实际执行的安全世界实例或初始化状态。

新增 `FUXI_M3_SMCI_LOOKUP_ARCH`，默认 0，仅显式
`--m3-smci-lookup --m3-smci-lookup-arch` 启用，要求既有 HLOS/object loader
诊断门控。新路径只有一次 `keymaster64` 查询，无 `keymaster` 后备查询。
旧格式仍保留用于历史对照，旧测试不是本候选新格式已通过的证据。

| 字段 | 新候选布局 |
|---|---|
| op / counts | 2 / 0x1011 |
| 名字 BI | 描述符 +12；offset40、size11，不含 NUL |
| 架构 BO | 描述符 +20；offset56、size4 |
| 返回对象 OO | +28 低32位句柄；+32 高32位必须为0 |
| 架构值 | ELF class1 或2 |
| 注册范围 | 8192字节，输入/回调输出各4096字节 |

名字、描述符、头、对齐/保留区和尾部须原样符合有限契约；回调页只接受既有的
空终结形式，非空回调数据拒绝。SMC a0/a1/a3 非零、未知架构/句柄、对象与现有
env/loader 句柄别名、错误同时返回对象或架构、任何未识别响应都保留注册页和
对象并驻留，不重试、不继续释放。严格拒绝只说明响应超出本探针认可的子集，
不能直接定性为厂商 ABI 错误。

只有 a0/a1/a3 全零、完整形状校验通过且对象/架构均零的非零对象错误才允许
只清理 loader/env/bridge。日志保留原始状态，内部 EFI_NOT_FOUND 不证明 TA
不存在。有效成功须返回独立远端对象与架构，随后仅 release TA、loader、env，
delete bridge。短句柄或架构值均不证明它与 ABL 使用同一实例。

## 验证与上机边界

`test_fuxi_m3_lookup_arch.py`编译实际生产入口，以合成 monitor/filesystem 运行
38项 ASan/UBSan 用例：class1/2、空终结/两种既有回调头、干净对象错误、逐类
响应损坏、含返回对象/架构的错误、别名句柄、四个收尾失败、分配失败及拒绝
后备名字。测试断言整页请求、调用次数/顺序、未知响应不释放、清页后才 free，
并检查既有128条基线后的报告缓存未丢失。没有实际 SMC、认证或密钥恢复。

`audit_fuxi_m3_lookup_arch_contract.py`另固定既有 NS 参考及模块哈希，从参考
结构编译五项偏移/对齐断言，并绑定部署 TZ 证据。它没有执行安全世界的 NS
反序列化，不能代替新格式的实机测试。完整资格也保留旧11项lookup回归。

候选仍先做只读 M1/M2 `/metadata` 已知文件检查并停 UFS，再进入有限对象查询，
最后在 USB 接收器前 PARK。没有读取密钥 blob、LUN4 TA、加载新 TA、getVersion、
configure、208、setVersion、恢复/生成/升级密钥、ICE、userdata 解密或 RAM 交接。
完整镜像、默认与 SCM-query 模块须独立构建并顺序资格检查；镜像 SHA、真实
退出码和源码提交绑定记入候选 REVIEW，设备测试另用独立 attempt。

实际照片需覆盖查询请求/原始 a0..a3、架构/对象或错误状态、释放或 retained、
bridge delete、UFS停止/路由与最终 PARK。未知状态不自动重启或重试。
查询命中只解除“当前格式是否能取得已有对象”这一疑点；实际 TA 身份/boot、
SDK 初始化服务、真正触发 -62 的返回分支和元数据明文哈希均是后续门槛。

## 本候选交付记录

完整镜像1,880,064字节，SHA256
`2c140f174ed784b398bbcd9cb3b73b09ea4cb484c87de53917c183366b75b542`。
默认与query模块均构建退出0，21项顺序资格全部退出0；交付FD/EFI/镜像与96项
源码一致。实际默认/query EFI没有SMC指令，显式诊断EFI有1条。固定board仍为
`1d071dae4618b0676d313cfbe1fc39689e6f139e`，框架仍为
`7e237de0aa81a8f38221134c752af2d71236cddc`的预先dirty上下文，未清理其他会话改动。
[规范候选证据](evidence/fuxi-m3-lookup-arch-candidate-20261030.json)记录来源和报告
摘要，真实退出码与REVIEW在忽略out下。此处为主机交付，实机结果仍pending。
