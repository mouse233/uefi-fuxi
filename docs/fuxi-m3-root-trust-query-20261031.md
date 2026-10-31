# M3：单次boot上下文观察候选

2026-10-31，B线feat/twrp-data-uefi，改动层UEFI/主机资格。独立候选
`out/m3-root-trust-query-v1`，承接311f有效上下文审计，目标是观察TA当前boot版本，
不用blob公开版本填造平台状态。当前实机结果以本目录后续记录与候选REVIEW为准。

## 固定契约与观察范围

默认关闭 `FUXI_M3_ROOT_TRUST_QUERY`，仅显式 `--m3-root-trust-query` 启用，要求
parked M2、HLOS/object、TA load/version/有界resume。排除recovery、密钥目录探针、
lookup、characteristics、date/setVersion。构建器同时绑定原A组configure证明和
本轮完整封装/失败审计，固定170000/20261005/20261005，不能自由改boot/vendor。

调用为只读M1/M2/LUN4 TA准备→UFS队列停止→root/open122/load64/getVersion→
固定configure一次→311f一次→验证/清页/释放/bridge delete→PARK。协议版本必须
精确为4/1/4/1012；UFS仍ready/poisoned时在分配/安全调用前拒绝。每次启动仅一轮，
没有恢复输入准备、begin/update/finish/abort、ICE、userdata解密或RAM对象交接。
源码/实际对象检查确保KEY_RECOVERY与SECRET_EXCHANGE关闭、恢复入口引用缺席。

ROOTCTX不是无状态查询：TA在首次需要时可能经qsee_prng_getdata在其私有RAM初始化
32字节MAC缓存（5b488）和有效标记（5b4e8），之后调用qsee_SW_Hmac。它没有调用
Android generateKey命令或修改既有metadata密钥文件；不能把这个行为描述成完全
不产生/使用密钥。candidate.json中的legacy m3_smci_no_keys对本候选为false，
m3_reads_recovery_inputs为false，两者含义分别标明。禁止把本轮“存储只读”扩大为
整个安全世界无RAM状态变化或外部SDK已完全验证。

独立query只输出boot整数。不能用它替代vendor有效槽、实际selector、完整SDK
初始化、ABL同实例或真实-62返回PC证明。loadFromBuffer也不证明新建TA实例。

## 请求、响应与内存归属

311f请求是固定23字节：4字节命令、map{4:16字节公开诊断挑战}。AIDL签名限定
16字节；此前TA孤立parser还接受其他长度，本候选主动只发匹配子集。没有调用
未实现的getRootOfTrustChallenge，也不把311e生成CSR当后备。

实参SMCI形状沿已观测op0/count424，注册0x82000，消息0x15000、回调页0x1000。
请求/回调头、全部未授权可变范围、输入字节、对象、布局、对齐和保留区逐项验证。
只接受已见空终结回调，不分发未知回调。SMC只续调同一interrupted调用，保留x6，
上限8；不是重发查询，永不在未知结果后重试。

成功ROOTCTX响应须status0、payload≤256且有界；wire只接受实际payload+8或原容量
两种长度形式，多余输出须全零。生产解析器只接受匹配TA的确定/最短CBOR子集：

```text
map{36: bstr(tag17 [
  protected=bstr(a10105), unprotected=map{},
  payload=bstr(tag40001 [bstr32, bool, uint0..3, bstr32, boot:uint32]),
  mac=bstr32
])}
```

两段32字节数据与MAC只校验长度并跳过值，不复制/输出/摘要；parser仅返回boot。
不存在额外字段/尾部的接受路径；缺失、重复/扩展map、非最短编码、超宽整数、
未知tag/算法/状态/长度均拒绝。**MAC没有验证**；日志明确structural observation
only / MAC unverified，不能作为密码学认证、attestation或完整解密证明。

成功configure必须符合原A组空输出容量形状；ROOTCTX成功必须通过完整结构检查。
只有这些成功才清整个注册范围并回写cache，然后允许后续release/delete/free。
所有非零TA/SMC、未知回调、畸形结构、未匹配版本或续调耗尽均立即停止，保持
注册分配原样，不擦除/release/delete/free。CPU独占且从未注册的TA extent仍按
既有规则擦除释放；这不代表注册范围已释放。没有超时后转DarwinBoot的路径。

## 离线审计，不伪造加密成功

固定TA SHA256 2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6。
`audit_fuxi_m3_root_trust_contract.py`绑定PRNG/HMAC导入与10条原始边，执行：

- 11组实际handler前加密路径，精确核对tag40001载体与MAC0结构；在服务前停止。
- 独立post-MAC编码片段使用明确合成的测试tag，验证tag17/map36真实封装字节；
  与前段分开，不拼成“实际认证成功”。boot202610时payload79、MAC输入108、
  COSE122、最终payload127字节。
- 六组缺boot标记/缺初始化/缓存miss-hit边界/PRNG短返回/HMAC失败。两个标记
  失败均-30，PRNG短返回-49、HMAC失败-1；只注入失败，不替代成功PRNG/HMAC。
- 五组输出/COSE容量控制；错误返回经过实际清理，私有stack键区96与载体区128
  擦除通过。观测到的全局写只在MAC缓存长度元数据；没有实际执行SDK服务，
  不宣称已穷尽其内部回调/持久化副作用。

1170项生产C/独立模型差分与ASan/UBSan/PROT_NONE；11项固定TA合成编码向量逐字
匹配。32项真实生产batch入口合成monitor用例覆盖完整成功、两wire形状、空回调
变体、改变MAC值仍只作结构解析、逐类损坏、错误/配置失败保留、UFS未停/分配/
版本拒绝、同一次SMC续调/耗尽。失败整页快照与128条报告基线后无丢失均检查。
主机monitor成功不是实际MAC服务成功；MAC变化仍能解析正是未认证边界的检查。

完整镜像、默认/query模块、实际AARCH64对象/EFI与顺序资格检查须在候选REVIEW
写明退出码与SHA。外部SDK/HMAC没有在主机上执行，不通过成功桩掩盖；实机若出现
超出契约的返回，只保留并停止。历史FSR400和M3/M4/M5未通过。


## 本轮主机交付

完整镜像1,884,160字节，SHA256
`0388aae26ec4df740ecc8aa523a7f6329b4525daf27b16b1b9dd3797bfb913da`。
完整固件、默认/query模块均构建退出0，最终26项顺序资格全部退出0，114项
当前源码绑定通过。实际Native对象/map归档live-objects；EFI含固定23字节查询
请求及A配置，恢复调用引用缺席，默认/query模块无ROOTCTX入口，SMC门控核对通过。

首轮最终交付检查漏新批次日志分支，仍期待旧load-only计划字符串而失败；
仅修正主机检查器的期待值，未改变固件字节。首轮日志/退出码和构建时sources
原样保留，recheck断言唯一来源变化为该主机检查器后重跑完整26项资格通过。
ROOTCTX初版合成monitor沿旧版本测试填1/2/3/4，已在完整构建前改用严格门控所需
已观测4/1/4/1012，旧测试模式不变；32项入口与27项恢复回归最终均通过。

规范摘要见evidence/fuxi-m3-root-trust-query-candidate-20261031.json；精确构建/
启动与源码提交绑定见out/m3-root-trust-query-v1/REVIEW.md。本轮尚未上机。
照片需要ROOTCTX configure/query状态、boot整数或失败状态、resumes、retained、
UFS stop与最后PARK。即使得到boot值，也不宣称vendor/selector/真实-62分支已解决。


## 2026-10-31 12:22：attempt-01 临时启动返回0，等待照片

用户确认已进入FASTBOOT后，互斥无其他任务，fcde91e可见；固定镜像/源码/114源/
26资格 --verify-only再次exit0。脚本核验product=fuxi、unlocked=yes、slot=a、
max-download-size=805306368。12:22:20–12:22:22 Asia/Shanghai，仅一次
fastboot boot，Sending0.040s、Booting1.539s、总1.580s，exit0。没有重试、flash、
分区写或slot变更。原始记录attempt-01/device-test.json，SHA256
`38fd82d49a03aafa7522c59298a2d5a28ca647b3dc4dcb8f09fd3610c8e1b055`；规范摘要docs/evidence/fuxi-m3-root-trust-query-boot-20261031.json。

当前没有屏幕照片，不能据工具成功判断UFS停止、ROOTCTX configure/query状态、
boot值、retained/清理或PARK。已请用户发送完整画面；不再次启动或续发命令。
实际SDK/boot/vendor/selector/-62返回PC仍未验证，M3/M4/M5未通过。
