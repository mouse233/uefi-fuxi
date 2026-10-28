# M3 TA lookup：loader 对象上的 keymaster64/keymaster — 2026-10-28

## 触发与目标

root/loader 生命周期已在 `m3-smci-loader-hlos-v3` 的 attempt-01 整条通过
（桥 → register → open UID122 → release loader → release env → delete，passed=1F）。
下一步要回答的是：KeyMint TA 是否已存在于 TZ。若 lookup 命中，就不必先恢复缺失的
`keymaster.bXX` 分片；若未命中，错误值能区分“名字不对/未加载/权限不足”。

本候选只增加 lookup，不加载 TA、不发送 TA 请求、不接触密钥。

## 固定证据

`IQSEEComCompatAppLoader.h`（SHA256 597124e1…2a06）定义：

- `IQSEEComCompatAppLoader_OP_lookupTA = 2`；
- `lookupTA(self, appName_ptr, appName_len, obj_ptr)` 以 `ObjectCounts_pack(1,0,0,1)`
  调用，即 BI1/OO1；名字是 ASCII，上限 `MAX_FILENAME_LEN = 64`。
- 本机固定 `smcinvoke_dlkm.ko` @1f18..1f84 为 `mov w1,#0x2`、`mov w3,#0x1001`、
  失败后再走 `firmware_request_from_smcinvoke`、随后 `b 0x2028`（lookup 复用分支绕过
  EI_CLASS 读取）。因此 lookup 命中不等于已确定 is64。
- `IQSEEComCompatAppLoader.h` 加入固定输入集；7 份输入逐一篡改均被拒绝。

名字来源：固定 `libkeymasterdeviceutils.so` 从 `/vendor/firmware_mnt/image` 优先
`keymaster64`，失败回退 `keymaster`。本候选按此顺序各试一次。

## 线格式

与 open 相同的 BI1/OO1：头 12 字节（loader 句柄、op=2、counts=0x1001），
BI 描述符在 +12（offset=32、size=名字长度），OO 在 +20，名字字节在 +32。
整页 4 KiB 输入 + 4 KiB 输出，仍在同一个 8 KiB 页内。

## 批处理与停止点

`plan=root/open122/lookup64/lookup/ta-release/release-loader/release-env/delete`

1. 桥 enable/create（已验证的 HLOS 配置）；
2. root register（null credentials，op5/counts1100）→ client-env 句柄；
3. open UID122 → loader 句柄；
4. lookup `keymaster64`；
5. 仅当第 4 步是“对象错误”（a0=a1=a3=0 且 a2≠0）时，再 lookup `keymaster`；
6. 命中的 TA 对象立即 release；随后 release loader、release env、delete 桥。

停止规则：a0/a1/a3 任一非零、头部回显不符、out 页 +8 起非零、命中的句柄非远端，
都立即停在 `BATCH stop=` 并保留页面与句柄，不重试、不擦写、不 free。
两次 lookup 都是对象错误时，仍完成 loader/env release 与桥删除（没有 TA 对象可释放），
最终 `stop=lookup-missing`、`result=Not Found`。这是唯一被解释的非零 a2；
原始值原样打印，不把具体数值写成“名字不对”或“未加载”的结论。

## 验证

- 11 个 lookup 批处理向量（ASan/UBSan，模拟 monitor）：64 命中、64 未命中后 32 命中、
  两者都未命中、inbound 响应、头部篡改、out 计数非零、零句柄、a3 非零、
  TA release 失败、loader release 失败、分配失败。
- 契约审计：op2、counts1001、BI offset 32、OO offset 20、名字上限 64；7 份固定输入
  逐一篡改拒绝；反汇编与线格式静态断言。
- 既有的 82 个 loader 向量、148 个仅 C2 向量、24 个桥向量继续通过；20 项交付检查退出 0。

## 边界

lookup 只回答“该名字能否返回对象”。不证明 TA 已加载到可执行状态、不证明版本/签名、
不证明 is64，也不产生任何 KeyMint 会话。命中后需要独立的大缓冲 send/getVersion 候选
（此前模型为 86016 字节、21 页 + callback 区）；未命中才需要恢复同版本 TA 分片。
