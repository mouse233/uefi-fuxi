# -62研究审查：DS与GLM分别评估（2026-10-31）

审查对象：`ramdisk-test/unixnu-62-research-ds`和`ramdisk-test/unixnu-62-research-glm`。
原研究文件未修改；本轮仅主机读取、哈希、独立反汇编与指令检查，没有设备访问、
厂商代码执行、指令模拟、固件构建或新的安全调用。以下文件行号对应审查时快照。

**结论：两份都能作为静态线索来源，均不足以宣称已定位历史-62根因或直接实施其修复方案。**
DS的代码追踪和材料范围更广，尤其升级处理器、命令表及初始化标志值得保留；GLM的
版本门/参数宏复核也有价值。但二者共同越过了历史输入等价、实际返回分支和运行态
上下文的证据缺口，且ABL可达性判断互相矛盾。

P1表示会影响下一候选或根因裁决的主要问题；P2表示应修正的证据完整性/表述问题。

## 1. 审查方法与固定输入

- 分别阅读RESULT、PATHS、COUNTEREXAMPLES、NEXT、PROGRESS和所附检查脚本。
- 两份检查脚本均经审阅后运行，输入manifest当前110/110匹配；GLM本地TA/ABL副本
  与规范输入逐字节哈希匹配。GLM脚本在发现不匹配时没有非零退出机制，因此本次
  还核对了实际输出，未单凭exit0采信。
- TA SHA256：`2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6`。
- 当前ABL A PE SHA256：`48de0c341840c30e99d483ebbbdc0df4de67bc971d76bd05477587ace87aab3b`。
- 使用本机llvm-objdump独立反汇编，并解析PE可执行节的B/BL目标；8项关键原始指令
  检查通过。B/BL枚举不等于穷尽间接调用，审查本身也不以“没搜到”证明全局不可达。
- 原研究文档哈希、独立汇编、指令检查归档于
  `uefi-twrp-data/out/m3-minus62-research-review-20261031/`，原文哈希在核验后保持稳定。

## 2. DS研究

### DS-1 / P1：把条件解释升级成“A已证明真实升级需求”

位置：[RESULT.md:168](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-ds/RESULT.md:168)、
[RESULT.md:357](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-ds/RESULT.md:357)。

研究自己在169、192行承认A/B实际输入与后来的TWRP公开快照相同未证，196行也承认
外部SDK/syscall负状态来源未穷尽，却在最终结论中将A的-62确定为vendor陈旧造成的
合法升级信号，并将upgrade-first称为生产修复。

后来的Android属性、未认证blob公开整数和两处-62立即数，能建立一个很有解释力的
模型，不能证明历史调用实际进入98c0，更不能证明认证后的字段就是20:22采集值。
属性值还不是同次UEFI启动中被平台验证并交给该实例的上下文捕获。扫描TA及一个SDK
RX段没有-62常量，也不能排除服务返回/算术/间接错误映射。

应改为条件结论：**若历史输入、认证后字段、当前槽和返回路径均满足指定前提，A的
vendor差异足以触发版本门；这支持研究升级语义，不构成实际根因或修复已确定。**

### DS-2 / P1：升级“成功 / -30 / -38”不构成唯一运行态判别器

位置：[NEXT.md:23](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-ds/NEXT.md:23)、
[RESULT.md:323](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-ds/RESULT.md:323)。

将-38直接判为boot旧/0，并以“boot匹配就升级成功”决定后续改头/初始化，遗漏了
其他字段、输入绑定、解析、认证和重包裹前提。升级处理器本身有OS patch、vendor、
boot、OS四个单调性比较，失败汇合到9d04=-38；仅凭一个返回码无法确定具体字段。
boot单项检查通过后仍有b564、37310等可能失败的步骤。版本门返回0时也有“不需升级、
输出为空”分支，因此status0本身不证明拿到新blob或boot必然满足所假定的关系。

关于初始化，这份研究发现5b520和0x201很有价值，但调用顺序需要补齐：

```text
begin解析：35154 → 352a8调用b9f4 → 成功才352d8调用310a8 → … → 98c0
upgrade解析：9aa0调用37034 → 3720c调用b9f4 → 后续解包 → 返回handler
upgrade后段：9c0c再次调用b9f4；非零在9c14改成-1000
```

b9f4在5b520!=1时确可返回-30。**早期升级解析器会原样传播该值**，所以不能简单
否定DS的-30路径；但它不是升级后段独有的门。若采用研究自己的“同实例begin已经
到版本门”解释，则同次begin已经通过更早的b9f4，不能同时把未初始化5b520当作该次
失败的独立原因。新启动/新实例仍需另证。后段错误映射与早期原样传播也不能混同。

应交付带明确入口/前提的返回路径表，而不是将观测码直接等同某个初始化或boot值。
当前没有理由仅凭此表补发0x201或将升级列为默认上机步骤。

### DS-3 / P2：ABL调用者枚举漏掉B尾跳，“唯一直接调用路径”证明不完整

位置：[RESULT.md:269](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-ds/RESULT.md:269)、
[NEXT.md:225](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-ds/NEXT.md:225)。

报告以8e74c的BL及w1=0推出唯一启动路径不执行0x208。独立解析当前PE可执行节得到：

```text
8e74c: BL 2a700
8b724: mov w1,wzr
8b728: mov w2,wzr
8b72c: B  2a700       ← 研究漏掉的直接尾跳
2abe0: BL 2b4ac
2b4e4: and w20,w1,#0xff
2b534: cbz w20,2b5ec
```

新增尾跳仍传w1=0，因此**这不是0x208实际会执行的反证**；但它说明BL扫描和函数指针
搜索不足以宣称调用者已穷尽，尤其fastboot路径还须绑定该尾跳/跳板的调用来源。
未知服务回调与其它组件不能因当前直接路径绕开某块而被整体排除。应把结论限定为
已核对路径与参数，而非当前手机整条启动流程的“已死”结论。

### DS-4 / P2：最新结论与旧正文仍并存，存在会改变修复决策的矛盾

位置：[COUNTEREXAMPLES.md:203](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-ds/COUNTEREXAMPLES.md:203)、
[RESULT.md:342](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-ds/RESULT.md:342)。

C24仍称“boot等于202610则版本门已通过，不会进入升级”，遗漏vendor等其余字段，
与最终“boot相同、vendor旧仍需要升级”相矛盾。RESULT 7.7的代码框一处推boot=0，
随后又使用boot202607，并预言0x208=-1；这些前提并未在框中闭合。它们没有像C21
那样逐段明确标为撤回记录，容易使后续agent引用到不同版本的结论。

应保留一份当前条件模型，把旧方案移入明确标注的历史附录；未证值不写成轨迹。

### DS可保留的结果

1. 固定TA命令表的16字节结构、f0/f1、b2a0分发及未配置flag检查，机器码支持。
   这是有效的独立重建；旧configure-gate审计已覆盖部分机制，不是新增实机轨迹。
2. 2114/3114→9a5c、-62特判、四字段单调性和重写字段/存在标志，静态结构可采纳。
   认证、重包裹、输出格式和真实成功仍不能据局部结构宣布完成。
3. 5b520/b9f4/201初始化是值得追踪的接口关系。独立复核还见ABL第一条44字节请求
   的常量头为201/12，后面才是208/64字节请求；它加强了两条独立命令的联系，
   仍不证明本轮实际发送或成功，也不应直接拼造其平台载荷。
4. 保留Android/TWRP库版本、slot A/B和实例身份不能混用的限定；XBL B历史配置只作
   有限旁证，加载flag不证明当前slot A发送208或其日期来源。

## 3. GLM研究

### GLM-1 / P1：把未认证后采字段与立即数扫描当作历史根因闭环

位置：[RESULT.md:12](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-glm/RESULT.md:12)、
[RESULT.md:91](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-glm/RESULT.md:91)。

R1称历史A/B必然来自9a1c，R3称vendor不匹配为实锤，末段称输入/返回PC等缺口均
不是宣布根因所必需。两处常量与后采字段并不能建立历史输入、认证结果或执行分支。
COUNTEREXAMPLES 1.2还把未覆盖来源压缩成仅ldrsb，遗漏SDK/服务的返回值及一般
数据流。研究自身没有新的设备数据或认证执行证据，不能把“解释一致”升级为必然。

相同问题也影响其排除项：-64→-62随configure变化、小查询成功，不能逻辑排除所有
wire/缓存/SMMU问题。1.4声称application ID/nonce仅在update/finish消费，不能据此
排除begin前的包裹键解包/认证上下文。30efc/30f58的认证调用返回先于31010版本门，
尚需完整参数/错误来源分析才能作排除。应恢复这些缺口，限定为条件版本门模型。

### GLM-2 / P1：fastboot→208“调用图已闭合”漏掉更早门控与函数间连接

位置：[NEXT.md:13](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-glm/NEXT.md:13)、
[RESULT.md:75](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-glm/RESULT.md:75)。

88668/886a8确实调用258b0，但研究没有给出258b0到2a700的有效调用/尾跳边。
2abe0属于2a700开始的独立函数，不能因为地址相邻便归入258b0。B/BL扫描还发现
8b72c尾跳2a700，研究未纳入。即使进入2b4ac，2b534先按w1低字节决定是否转入
2b5ec回调路径；后面的2ce70才读取另一个参数相关栈槽。仅追arg3==0遗漏前门。

所以不能据此推“fastboot在结构上会尝试208”或偏向boot=202610。应补齐函数边界、
尾跳/跳板和至少两个门控的数据流，并保留发送是否成功和实际App是否同实例的未知。
本审查也没有反向宣称手机必定未发送208。

### GLM-3 / P1：用待解密blob的版本来填平台状态，不是已验证修复

位置：[NEXT.md:73](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-glm/NEXT.md:73)、
[RESULT.md:76](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-glm/RESULT.md:76)。

方案把vendor改为blob的20260801，并建议用blob的boot202610构造208，视为“与ABL
对齐”。这把被验证对象的值反过来作为平台可信上下文来源；未证明真实平台就是这些
值，也没有给出完整平台记录、初始化权限与一次性生命周期。即使作为隔离变量的诊断，
也不能因此称为生产修复或由一次返回直接反推出旧槽值。

机器码显示208在bde0置一次性标记、bdf4写boot，**之后**还调用404b4。因此它既非
只读探针，也可能在后续失败前已改变状态。内存内upgrade同样会重新包裹blob，不能
仅以“不写分区”视为落在当前不升级/不捏造初始化的工程子集中。作为未来建议可讨论，
本研究不足以批准直接上机；不能用放宽既有边界来验证其根因假设。

### GLM-4 / P1：未知错误payload的摘要不能预先保证“无密钥材料暴露”

位置：[NEXT.md:39](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-glm/NEXT.md:39)。

研究一方面承认40616字节区域内容完全未知，另一方面建议记录非零计数与SHA256并
断言无材料暴露。错误payload可能是容量字段、残留、认证相关数据或其它格式；未明确
分类其来源前，不能把未知区域整体摘要当公开字段，也与现有不输出材料摘要的边界
不相容。应先静态确认wrapper/错误格式和允许记录的固定头字段；内容不明时继续
隔离保留，不直接读取、摘要或输出整个区域。

### GLM-5 / P2：把TA命令分发器误认成授权遍历函数

位置：[RESULT.md:38](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-glm/RESULT.md:38)、
[PATHS.md:155](/Volumes/External/VSCode/UniXNU/ramdisk-test/unixnu-62-research-glm/PATHS.md:170)。

b2a0明确调用2a700/2a710取89项命令表，按16字节步长比较命令号，f0触发dd7c的
未配置检查，随后调用命中handler。这里的表项不是blob授权tag。GLM因此寻找“b44c
授权遍历到30d9c认证辅助”的下行连接，实际应把该分发器放在handler的上游。
这不推翻其flag位分析，但需要重画-64链，避免在不存在的认证子路径上继续分析。

### GLM可保留的结果

1. 版本门精确相等比较、四字段偏移、OS patch规范化和FBE标志早退的复核正确。
   A/B共享OS patch/vendor参数确实未独立控制vendor；这是条件模型，不是历史根因。
2. 升级路径的四字段单调性结构可采纳，但不是boot就绪后必成功的充分条件。
3. fault7前没有解释payload内容的观察正确，应与其不合适的整区摘要建议分开。
4. 独立固定输入校验和本地汇编便于复核；“唯一写者/永远索引0”仍应限定到所核对
   的映像及加载布局，不能排除SDK服务/加载器间接影响。

## 4. 两份研究之后，可以更新什么

| 内容 | 审查处理 |
|---|---|
| 历史A/B -62的实际返回PC与输入等价 | 仍未知，不能从常量扫描与后采字段倒填 |
| 升级处理器、单调性、字段重写 | 接收为固定TA的静态结构，待完整协议/副作用核验 |
| HLOS初始化检查 | 接收并补充begin/upgrade解析都先调用b9f4；与后段-1000映射分层 |
| ABL 208可达性 | 两份相反结论都需收窄；新增B尾跳和w1前门是应纳入的事实 |
| 下一步直接发201/208/2114或改boot头 | 本轮不批准；当前没有可直接采用的修复候选 |
| 未知payload整体计数/摘要 | 不作为已审定公开观察；先核定响应字段语义 |
| M3/M4/M5、FSR400、真实密钥恢复 | 不新增通过或解决声明 |

优先利用现有离线材料补齐b9f4的全链参数/失败传播、ABL尾跳与双门控、升级请求/
响应与厂商codec逐字节对照，再决定是否需要一个只记录白名单公开字段的独立候选。
“版本不匹配/合法升级”目前是有依据的解释方向，仍应与已证实的历史根因分开。
