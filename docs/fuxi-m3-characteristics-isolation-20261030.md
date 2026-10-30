# M3 特性探针隔离修复与恢复上下文复核（2026-10-30）

B 线 `feat/twrp-data-uefi`，改动层为 UEFI、主机测试和候选资格工具。
独立候选为 `out/m3-characteristics-isolation-v1/`；镜像、构建和检查结果以该目录
`REVIEW.md` 为准。本轮不操作手机，不改变 M3/M4/M5 的未通过状态。

## 修复的两处生产缺陷

`FkmProbeCharacteristics` 原先在交换/寄存器、描述符、piggyback 或响应长度异常后，
虽然设置后端隔离，却立即擦除注册共享页和请求。未知完成时页仍可能被安全世界
引用，这不符合恢复后端既有的保留规则。现改为：提交后的任何失败均保留共享页、
请求字节及长度；设置隔离和公开 fault；仅清除尚未发布的局部版本字段和栈副本。
成功响应完整验证后才允许擦除共享页和请求。

原先 CBOR 解析失败没有隔离，`FnuRunRecovery` 也忽略探针返回值，因而还能发起
begin。现将解析失败以及非零 TA status 全部作为该诊断会话的停止条件；调用方
独立检查返回值，即使错误发生在提交前，也不进入恢复、reset、release 或 delete。
失败时恢复输入保持 `FkrPrepared`、`mRecoveryAttempted=0`，保留会话并 PARK。
这是一项保守的诊断停止策略，不把负 status 当作恢复认证或会话关闭证据。

原测试把“失败后全部清零”和“畸形 CBOR 不隔离”断言为正确，已纠正。新增生产
特性入口测试编译真实 `.inc`、后端和交换层，而非只分别测试探针与普通入口。
候选资格工具现在强制执行该组合；缺少组合报告不能通过镜像交付检查。

## 固定调用链与命令语义

可复现工具为 `tools/audit_fuxi_m3_recovery_context.py`；固定 recovery、厂商库、
TA 的 SHA256 和十段代码哈希见
[`evidence/fuxi-m3-recovery-context-20261030.json`](evidence/fuxi-m3-recovery-context-20261030.json)。
输入 recovery 取自既有 A16 展开档，沿用 A17 比较记录中的相同文件哈希；不把旧
recovery 在当前系统的解密失败忽略掉，也不宣称重新采集了 TWRP 运行轨迹。

| 固定位置 | 本轮能复核的事实 | 仍不能推出什么 |
| --- | --- | --- |
| recovery `0x2501e8..0x250220` | 等待 Binder 服务、`IKeystoreService::fromBinder`，以参数1和虚表调用取得接口 | 没有完整覆盖 keystore2 的运行时适配、升级/重试与初始化行为 |
| libqtikeymint `0x1b134`、`0x31e5c` | AIDL begin 调用 `keymint_begin_operation`，后者选择 `0x310f`，此前调用 `spu_init` | 不能用另一通用 HAL 的21/25分支替换实际 AIDL 路径 |
| libqtikeymint `0x2e44c..0x2e480` | 非 legacy configure 先调用 `keymint_set_version`，随后构造 `0x2116` | 不证明本机可忽略 setVersion 的历史 -40，或现在应重发它 |
| libqtikeymint `0x2e2bc..0x2e2cc` | setVersion 使用 `0x3121` 和整数200 | 不证明200是 OS 版本或可据此随意改变 TA client 槽 |
| libqtikeymint `0x2e644` | `generate_key` 选择 `0x2108`（另一 SecurityLevel 分支为 `0x2508`） | **`0x2108` 不是此前建议的 upgradeKey** |
| libqtikeymint `0x2f52c` | 非 legacy、TEE 的 `upgrade_key` 选择 `0x2114` | 只确认语义，不调用，也不证明无持久化副作用 |

因此恢复记录末尾的“v7 configure → upgradeKey(0x2108) → begin”提议撤回。
其命令认定本身错误，而且越出当前拒绝生成、升级和持久化的恢复子集。
交换层没有加入这些命令；新增反例明确拒绝21/25/31组生成/升级以及 `0x3121`，
在 SMC 和缓存维护之前隔离，保持共享页不变。

## 版本字段与错误归因的修正

固定 TA `0x98c0` 的比较包含 blob 格式版本以及 OS、OS patch、boot patch、vendor
patch 四个值。只读到 OS/OS patch 两个整数，也不足以唯一识别 -62 的产生条件。
此外 `0xb8ac` 会把本轮原始 OS patch 槽的 `20261005` 规范化为 `202610` 后比较；
不能将响应中的 OS patch 直接与 configure 的原始 YYYYMMDD 值判等并归因。

以公开合成结构执行真实版本检查指令，六组对照为：全部匹配返回0；格式版本过低、
OS、OS patch、boot patch、vendor patch 各自单独不匹配均返回 -62。没有使用真实
blob、恢复密钥或安全服务，也没有据这些对照确定 v3/v5/v6 实机命中了哪条分支。

此前 -33 的“keyId 不在表中，因此旧格式/不允许此命令”降为静态候选解释。
直接 `bl` 图会遗漏导入回调、函数指针与 `br` 跳板；本轮固定 TA `0x2480` 就是
`br x16` 跳板。未观察 TA 内部日志或完整执行路径，不能声称所有错误来源已穷尽。
同样，fastboot Booting 用时不能证明具体 TA/RPMB 往返或其副作用。

## 下一门槛

先以本候选验证失败后只保留、不继续调用的实机行为；它预计在既有 -33 处停止，
不会再像 v6 那样继续发送 begin。该验证不解释 -33，也不推进密钥恢复成功等级。
随后补齐 TWRP/keystore2 实际初始化上下文与有效属性对照，保持无秘密日志、无
生成/升级/写回；继续做恢复上下文的差分证据，不按错误码猜测新命令。

真实恢复、convert/HWKM/ICE/DUN、userdata 明文、fscrypt 与 RAM 交接仍分别待验。

## attempt-01：-33 后跳过恢复并 PARK（15:55 Asia/Shanghai）

用户确认fastboot，互斥和设备身份/解锁/slot_a核对后，固定镜像80c605a1…62b9541
单次临时boot成功（Sending0.040s、Booting1.640s、exit0）；无flash/分区写/改slot。
30项资格与86个提交/当前源码在启动前重新绑定，原始记录在候选attempt-01。

照片SHA256 `8fa93c39ed6301c498056d78bbcbcd3808abb2754d87123daec51c2bfd9d4ada`
确认CONFIGURE status0/Success；CHARACTERISTICS -33、payload40660/wire40668，
随后`RECOVERY skipped`、state1/stage0、commands1/resumes0、attempted0/retained1；
最终stage=m3-characteristics，PARK/no USB receiver/no handoff。

这是本次负状态分支停止后续begin的实机证据，不是共享页物理内容回读或全部未知
完成分支的硬件验收。保留不改页的证明仍来自绑定源码和主机快照测试。UFS stop1/
db0/tdb0/run0可见，但历史FSR0x400仍未解释。-33根因、真实恢复与M3/M4/M5仍未通过。
