# M3：-62 同次启动公开输入观测候选

2026-10-31，B 线 `feat/twrp-data-uefi`，改动层为 UEFI 与主机资格检查。
独立候选 `out/m3-sameboot-public-v1`。本轮从 DS/GLM 的独立审查继续，先补齐
实际输入关联证据；不把研究中的升级/平台初始化假说直接接入设备。

## 要补的证据与实验选择

历史 A/B 首次 begin 都收到外层 `FFFFFFC2`（-62），但公开 blob 字段来自后来
一次 TWRP 采样，尚未证明与触发历史错误的输入一致。格式/字段校验只是静态
可达来源之一，实际返回 PC、认证错误传播和安全世界真实实例仍未定位。

本候选沿 A 组的 loadFromBuffer → getVersion → 一次 configure → 既有恢复流程，
保持 OS 170000、OS/vendor patch 20261005。只增加首次 begin 前的 CPU 解析和公开
日志，不组合 lookup 新路径，以免同时改变获取 App 的方式。这是独立的新启动
对照，不能补写历史 A/B 的真实输入。此前 lookup-only 实机所得对象4/架构2仍是
单独证据；沿 lookup 对象验证只读版本方法的工作尚未实现。

## 公开字段与严格边界

新开关 `FUXI_M3_RECOVERY_PUBLIC` 默认为0。构建参数 `--m3-recovery-public` 要求
显式 configured recovery，排除 characteristics；原有 recovery/binding、UFS
停止、版本和 object/HLOS 等门控不变。

在 `FnuRunRecovery` 进入秘密交换会话之前，直接解析 `mRecoveryWork->Blob`。
恢复核心检查 Request.Blob 指向该数组、长度一致；序列化器直接把它放入首次
begin。集成测试从 fake monitor 收到的真实生产 wire 中核对完整合成 blob，
并核对 App 与 configure/getVersion/load 流程的固定句柄一致。测试没有真实密钥。

日志只包含：

- loadFromBuffer 来源标签、传入的 App 句柄；不据此声称底层实例新建或与 ABL 同实例。
- 外层 format、公开前缀/完整 blob 长度；标明 unauthenticated。
- software=0 / hardware=1 两域的 OS、OS patch、boot patch、vendor patch、algorithm。
- presence mask 的 bit0..4 依次对应上述五字段；缺失字段打印0，须结合 mask 解读。
  `fbe` 只表示白名单 tag 的 true 值存在，不含任何 FBE 材料。
- configure 实际固定请求对应的 OS/OS patch/vendor patch 与 App；boot-state 明确
  unobserved。GetVersion 和 configure 日志都不能当 TA 内部实际 boot 状态读取。

外层要求 definite array 4..16、magic `4b4d4b44`、无符号格式/不报告的第三项，
第四项为1..2048字节授权 bstr。两授权域恰为0与1，不允许重复域；每域 map≤128，
不允许重复/超宽 tag。白名单版本/algorithm 只接受 uint32；FBE 只接受 CBOR true。
未知公开项仅有界跳过，最长嵌套8，拒绝保留/非最短/不支持编码。
解析在第四项结束处停止，不访问加密尾部；不输出 opaque ID、任何原始字节、
未知 tag/value、application ID、nonce、密钥或它们的摘要。

格式版本不等于 required 仅记录，不改写或假造认证结果。解析失败则不发 begin，
擦除可由 CPU 安全清理的准备输入，走既有 pre-begin 会话收尾；已进入秘密交换后
的未知状态继续沿原隔离规则保留，不因公开解析结果放宽 release/delete。
本轮不增加任何 TA 命令，仍无升级、生成、201/208、setVersion、ICE、userdata
解密或 RAM 对象发布；不写分区，最终 PARK。

## 主机验证与实机待采集项

新解析器 `M3BlobPublic.h` 用944项合成输入与现有流式 Python 读取器做差分检查，
覆盖格式/第三项宽度、字段缺失/零值/超宽、重复域/tag、FBE 类型、截断、非最短
编码、嵌套/容量边界和800项固定随机种子变异。每项把可访问前缀放在页末，
下一页 PROT_NONE；接受项可声明仍有尾部，任何误读会直接失败。ASan/UBSan。

新观测入口29项生产流程合成用例：原27项配置/恢复/未知状态快照回归，另2项
准备后损坏公开输入，验证 configure 后不发 begin 且完整有限收尾。新模式核对
App 和完整提交的合成 blob；既有17项未配置、27项 configured 测试继续独立运行。
主机检查不能证明实际 TA 认证、真实 -62 的返回分支或设备密钥恢复成功。

完整构建/资格、镜像摘要及源码提交绑定将随本轮结果写入规范证据与候选 REVIEW。
实机照片需覆盖 PUBLIC 的两域/mask/format、CONFIGURE 同 App/固定值/响应、
RECOVERY 原始 wrapper 状态及 state/stage/commands/resumes/retained、UFS停止和
最后 PARK。若照片仍为 -62，只能用同次公开输入排除部分解释，不能据此唯一归因。

本轮尚未操作手机。历史 SMMU FSR400、实际 boot/初始化与真实错误 PC 仍缺证；
M3/M4/M5 未通过，无免 USB 重传声明。

## 完整候选交付

完整固件、默认与 SCM query 模块构建均退出0；最终31项顺序资格全退出0。
镜像1,888,256字节，SHA256
`035fb1adeb3adc2718ec0896539467ce4bd37ec8042061845ccdc5064a432b15`。
实际 AARCH64 恢复对象与 linked map 归档在候选 `live-objects/`；交付检查验证
观测标记确实位于封装 FD 中的本次 EFI，公开请求与配置证据绑定一致。

首轮最后一项交付检查发生 Python 局部变量初始化顺序错误：先检查 EFI 标记、
后读取 EFI。已移动检查位置，只变更主机检查器，不修改固件。首次失败日志、
退出码及构建时 sources 单独保留；重查前断言唯一 source manifest 差异是该检查器。
最终完整31项资格重跑退出0。原先两个新测试编译参数的字符宽度/格式类型错误也
已在完整构建前修正，新测试均在最终资格中重新执行成功。

规范摘要见 `evidence/fuxi-m3-sameboot-public-candidate-20261031.json`；源码提交、
精确启动命令、固定输入和剩余实机边界见 `out/m3-sameboot-public-v1/REVIEW.md`。
硬件结果仍 pending，本轮尚未发起设备操作，不能宣称 -62 已解除。


## 2026-10-31 11:12：attempt-01 临时启动完成，等待照片

用户确认FASTBOOT后，互斥检查无活动设备任务，fcde91e可见。固定镜像/源码提交/
102项源/31项资格的 --verify-only 再次退出0；启动脚本核验 product=fuxi、
unlocked=yes、slot=a、max-download-size=805306368。11:12:44–11:12:46
Asia/Shanghai 仅一次 fastboot boot，Sending0.040s、Booting1.592s、总1.633s，退出0。
没有重试、flash、分区写或slot变更。原始记录 attempt-01/device-test.json，SHA256
`4e54b946c42c3d4351d22610c9b84c660754a6095cb854b066ec1c03b5b95499`；规范摘要
`docs/evidence/fuxi-m3-sameboot-public-boot-20261031.json`。

当前没有屏幕照片，不能据工具成功判断到达PUBLIC/CONFIGURE/RECOVERY、UFS停机、
真实 -62 状态或最后PARK。保持等待照片，不再次启动。照片应清晰覆盖PUBLIC两域/
mask/format、CONFIGURE同App/日期、RECOVERY响应status与state/stage/commands/
resumes/retained及最终停点。真实分支/boot/实例与M3/M4/M5仍未通过。
