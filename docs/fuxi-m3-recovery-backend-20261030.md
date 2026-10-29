# M3 恢复后端：AIDL 调用链、wire codec 与 SMCI 封装（2026-10-30）

接 [现存密钥恢复核心](fuxi-m3-key-recovery-20261030.md)，本轮新增独立
`M3KeyMintBackend.c/.h`：把恢复核心的 typed callbacks 转为固定 A17 TWRP
参考的 CBOR 和 IQSEEComCompat sendRequest 内联报文，严格解析响应与维护操作归属。
库通过 `FKM_EXCHANGE` 接收一次原始交换结果；**没有 live SMC callback 或驱动入口**。
未读手机密钥、操作设备、发送 configure、构建启动镜像，M3 未通过。

## 纠正命令选择的范围

此前只审计了通用 `begin_operation` 中的 `0x21xx/0x25xx` 分支。本轮沿 AIDL
实际调用点追踪，得到更具体的链；不改写上一轮已固定的历史报告：

| A17 libqtikeymint 位置 | 调用/命令 |
| --- | --- |
| AndroidKeyMintDevice::begin `0x1b134` → `0x31dac` | `keymint_begin_operation`，`0x31e5c` 发 `0x310f` |
| AndroidKeyMintOperation::update `0x1f58c` → `0x3219c` | `0x32268` 发 `0x3111` |
| AndroidKeyMintOperation::finish `0x1f8c8` → `0x32380` | `0x32430` 发 `0x3112` |
| AndroidKeyMintOperation::abort `0x1fa58` → `0x2fe28` | 通用 abort，TEE/非 legacy 子集使用 `0x2113` |

固定 TA 表中 `0x310f/0x3111/0x3112/0x3113` 与对应 `0x21xx` 分别共用
`0x8984/0x8fa8/0x9350/0x94f0` 处理函数。不能因上一轮列举了21/25组，就认为31组
不存在；本后端按上表 AIDL 路径编码，abort保留通用TEE路径，不任意切换命令号。

固定 recovery 的 Keymaster 构造点 `0x25020c` 向 keystore 服务传 security level=1；
通用 abort 的选择还受 HalDevice SecurityLevel 和 isLegacy 影响。已有 getVersion
照片字段 `[4,1,4,1012]` 对应先前审计的非 legacy 判断，但仍不是本轮 live session。
后端只允许调用者独立确认 A17 AIDL TEE 会话，不覆盖 StrongBox/其他版本。

## 编码与解析证据

`tools/audit_fuxi_m3_recovery_wire.py` 先固定 SHA256 与 ELF 范围，再在 Unicorn 内
执行请求 serializer、三个响应 deserializer 和其 QCBOR 依赖。合成输入只含公开模式
字节；libc/分配/km_memscpy 有界模拟，codec CFI 仅接受固定合成对象身份；无 TA、
KeyMint操作、认证或安全世界成功 hook。按此前 CTR_EL0/SIGILL 记录在 macOS 沙箱外
执行；本轮没有在沙箱内再次初始化 Unicorn。

输入仍为前一轮固定 recovery/TA 与 TWRP libqtikeymint；新增依赖 libqcbor SHA256
`bda86553e45dce1da186830619909b3bae95ff9a91ce3a5df94fa0801c8b2500`、deviceutils
`1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2`。
这组 TWRP 库与当前 Android runtime 库须区别绑定，不能混用其 configure 参数。

确认的 wire 子集（外层为 LE32 command）：

- begin：CBOR map，label22为参数个数6；mode/padding/MAC、application ID、nonce，
  再补 purpose 参数 `0x20000001=1`，最后 label23为 key blob。
- `addParams` 用 `ldrsw` 将32位tag扩成有符号64位 label。因此 application ID
  `0x90000259`、nonce `0x900003e9` 实际编码为**负数 label**，不能编码成正uint32。
- update：`{34: handle, 35: bstr(input)}`；本子集不传额外认证参数。
- finish与abort请求：`{34: handle}`，finish不重复传入已由update消费的输入。
- 成功响应：begin `{22:0,34:handle}`；update `{22:0,36:bstr(output),37:consumed}`；
  finish `{22:0,36:bstr(output)}`。三个响应模型均交给真实厂商解析器验证。

独立 C encoder 与厂商输出逐字节比较12个向量：blob长度1/208/4096，覆盖1与64位
handle边界；独立 C decoder 验证上述3个向量。解析器故意只接受 definite/shortest
编码、零输出授权参数，拒绝重复/未知label、尾随数据、超长/错误类型及零begin handle。
这不保证设备响应一定落在该保守子集内；未知格式必须隔离而非放宽后继续。

## SMCI 封装与资源归属

新库无分配、日志、注册或SMC API。调用者提供已独立验证的 app、0x16000字节
页对齐共享区与一次交换回调。`SessionVerified` 是调用者断言，当前无生产调用者
建立它；为false时拒绝初始化。不得据此把硬件资格说成已完成。

固定 op0/counts0x424，BI4/BO2/OI4（四个null input objects）；请求与40KiB QSEECom
响应预算按厂商 align4 分配，再按8字节对齐逐个构造内联描述符。前三组begin报文
与既有独立 Python `build_send_request` 模型完整逐字节一致，包含padding与空对象。
输入报文0x15000，外层piggyback输出页4096字节，总共享区0x16000。

回调返回后分别验证EFI transport、SMC四寄存器、空piggyback、全部描述符、输入
不变性、保留区与响应边界，再解释TA status/length及CBOR。只接受已观察过的空
piggyback形式；不执行listener/callback。未知响应、活跃回调、输入变更、超长或解析
失败均同时隔离后端和恢复核心，保留私有请求副本、共享页和操作，不发下一命令。

已知update/finish TA错误原样传给恢复核心，仅允许一次abort。abort错误也隔离并
保留，不能因命令返回过就清除操作归属；该点由本轮反例测试发现并修正。
仅成功finish/abort才清除本地operation handle。命令完成后的共享页清理不释放app/
bridge，后者仍由会话调用者管理。真实安全世界的finish/abort关闭证据仍待上机验证。

## 绑定上下文仍须核实

固定 recovery `0x247aec..0x247b14` 分配并清零绑定对象（含state与空vector）；
`0x24b1dc..0x24b210` 在state0首次使用时写state2，不追加seed；state1才追加seed。
`setKeyStorageBindingSeed` 可从state0设为state1。本轮完整静态反汇编未发现直达该
setter 的 `bl`；这不能排除间接调用，也不能单独证明手机现存密钥的创建/绑定上下文。
因此没有把 `FkrPrepare.BindingChecked` 自动置真或默认空seed。

下一项具体工作是核实本机绑定上下文，并把已验证会话的 app/shared range 接到真实
`FKM_EXCHANGE`：物理范围、bridge/cache、同一SMC的有界resume、终态及会话关闭。
旧查询诊断包含缓冲区字段日志，不能未经审计直接复用于带秘密的恢复请求。
条件成立后才能做一次现存密钥恢复，再进入convert/HWKM/ICE/DUN及单块明文对照。

## 验证结果与范围

独立包 `out/m3-recovery-backend-v1/REVIEW.md` 记录命令、SHA与边界。

- 53项主机用例，ASan/UBSan：生产后端→恢复核心；覆盖异常SMC、描述符/输入篡改、
  callback/piggyback、响应长度、解析错误、零消费、TA失败及abort失败隔离，另有2000
  个确定性有界解码输入。此处transport返回是测试模型，未做真实TA/GCM认证。
- 固定厂商/QCBOR 12请求+3响应对照，以及3个完整SMCI报文独立模型对照通过。
- 默认与query两种AARCH64模块构建、源码/EFI及4个实际编译对象绑定检查通过。
  后端对象无外部依赖；默认两个EFI无SMC，query仅既有DataProbe INFO为1条。
- 初次响应模拟缺少KeymasterUtils上下文/内存复制模型、初次主机编译缺EDK2 host
  flags；反例还发现abort错误时后端未同步隔离。修正后的最终检查全部退出0。
  早期模块归档为 `modules-no-smc-before-abort-fix`，不作为最终资格记录。

库尚未由固件入口调用，最终EFI与上一轮相同（未使用函数会被链接器丢弃）；因此另查
实际AARCH64对象，不能用EFI哈希不变证明新增路径已上机。没有新FD/启动镜像、真实
KeyMint恢复或userdata明文，历史SMMU FSR400未解释；M3/M4/M5均无新增实机通过。
