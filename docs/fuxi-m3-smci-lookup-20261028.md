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

## attempt-01 实机结论：lookup 被对象层拒绝（a2=2）

照片IMG_7178..JPG，SHA256 ef1dd1d215a187e9f7852a473628e76bd6b56a3a80a2cf68b249cc1a166c5192。root/loader 链路仍完整，但两次 lookup 都被对象层拒绝。

- 桥：create 参数C697A006/C697A006/2200/3，返回a0=0、a1=0、a2=14194A61；delete用14194A61返回全零。
- register→2、open UID122→3 均与上一轮一致；lookup 在句柄3上执行。
- lookup keymaster64（BI offset=32 size=11）：a0=0、a1=0、**a2=2**、a3=0；oo=0/0，没有返回对象。
- 回退 lookup keymaster（size=9）：a0=0、a1=0、**a2=2**、a3=0；同样没有对象。
- 收尾：loader-release(3)、object-release(2)、bridge-delete(14194A61)全部成功；
  BATCH stop=lookup-missing passed=1F env=0 loader=0 ta=0 retained=0；released bytes=2000；
  result=Not Found；PARK 与 cached report end 可见。
- 固定头把2定义为OBJECT_ERROR_INVALID（不支持/未识别的请求）；AppLoader另有10..26的具体错误，
  2不在其中。**因此不能写成“TA不存在/未加载/名字不对”**：本轮只确认对象层拒绝了该请求。
  未确定的可能包括：该名字不在元数据、null凭据使loader拒绝、部署固件的请求形状不同、
  或open UID122返回的对象在此固件上不实现lookupTA。
- UFS stop=1、db=tdb=run=0、hcs=0000010F、is=0；SMMU GFSR=0、FSR=00000400 仍残留；
  M2 的10527字节与SHA256 14f3d867…0991仍一致。
- 镜像e252d7d308318a64d4ba06e9fccf45ec9f14b85508fb689a984170a5e6ddbfa1与提交67e70d9c7b57063a661b98ca73b7fcae8dff55dd的56个源码绑定、20项检查、11/82/148/24向量有效。
  无TA加载、无sendRequest、无密钥、无解密。
- 下一步应先把“名字是否存在”和“调用形状是否被接受”分开：需要独立证据确认部署固件里
  keymaster 分片的准确名字（例如从设备只读查看 /vendor/firmware_mnt/image），
  再决定是恢复分片走 loadFromBuffer，还是先做一次可区分的接口校准实验。
