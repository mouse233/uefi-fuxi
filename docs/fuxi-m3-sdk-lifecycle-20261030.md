# M3 SDK 服务边界与 UEFI 会话生命周期（2026-10-30）

本轮继续离线分析已与slot A分区哈希匹配的TZ/SDK。结论是：**当前UEFI的版本查询、
configure及恢复在源码和主机模拟中使用同一App句柄，隔离后不会继续卸载；但这些
事实不证明该对象复用了ABL实例或继承了启动字段。** SDK初始化也不能只看返回0。
实际boot值、字段来源、实例关联和-62返回PC仍未捕获，M3/M4/M5未通过。

只新增主机审计/观察器和文档，没有手机访问、固件修改/构建、新安全命令、生成/
升级/写回。默认开关和隔离策略不变，旧A/B各91源码绑定保持完整。

## 固定输入和主机执行边界

TA仍为2fc838a8…43cc6，TZ为d4b8afbe…60d418，后者补零后的SHA与2026-10-30
22:31:38 TWRP两轮tz_a摘要相符。工具重新核验身份报告的采集器源哈希和TZ对应。
通过TZ动态表/定义符号解析五个入口，不凭字符串或地址邻近猜函数：

| SDK符号 | 模块相对地址（基址0xd860f000） |
| --- | --- |
| cmnlib_init | 0x3178 |
| GPAppLib_init | 0x1071c |
| GPAppLib_appInit | 0x1091c |
| qsee_is_sw_fuse_blown | 0x32258 |
| qsee_cfg_getpropval | 0x2d8d4 |

只映射该内置模块的三个PT_LOAD段；执行仍在主机Unicorn私有内存中。TA两个
JMPREL导入5a160/5a190按符号绑定到对应SDK函数；索引仍为前轮验证的RX零常量。
TLS、栈和上下文全部为公开合成输入。对象调用、分配器、未覆盖初始化辅助函数
或syscall在执行前停止；SVC/HVC/SMC和指令数上限另有拒绝控制。
SDK以固定TZ虚拟地址映射，未做完整SDK重定位/加载；所跑片段只用TLS/参数，
不把这种局部映射当作真实SDK环境。TA侧仍应用前轮固定相对重定位。
没有原生运行厂商代码，没有实际外部初始化或把服务桩成成功。

## 初始化链的具体边界

cmnlib_init读取调用方上下文并设置TLS。两种合成输入分别在对象调用跳板0x19b0
或未覆盖本地初始化辅助函数0x44前停止；未继续对象操作或推断整个入口通过。
GPAppLib_init在首次分配器0x311a4前停，实际请求56字节，未分配或替代成功。

GPAppLib_appInit从TLS+0x58读取对象对，经0x19f0跳板调用op1、counts0x10、
4字节BO。这个对象的真实来源/权限与返回值没有捕获，不给它臆造服务名称。
两个对照在对象调用前保留真实函数帧，随后**只从调用返回点0x1095c注入负状态**
-1或-65536，运行真实收尾指令：

```text
函数返回：0
TLS+0x90：ffff0000
TLS+0x94：3
```

这证明入口返回0本身不能代表外部操作成功；错误可留在TLS中。它是明确的负
返回反事实，不是手机实际服务错误、整个SDK初始化结果或错误根因。片段中boot
全局未写仍只是片段事实；其余初始化/对象服务没有运行，不能据此断言实机boot0。

## 208 前置门与收尾已追到具体 SDK 服务

208处理器的前置194fc经TA PLT310/GOT5a190进入qsee_is_sw_fuse_blown。
真实指令以fuse ID1、1字节输出调用该SDK，再准备取得UID22服务；审计停在
SDK 0x2e014服务解析器入口，未解析真实对象或执行熔丝服务。因此208不是可以
仅根据日期格式拼包试发的入口。本轮没有读熔丝或发送208。

208写标记/boot后的404b4会调用18d4c。18d4c经PLT2b0/GOT5a160进入
qsee_cfg_getpropval，实际参数为enable_spu_uefi、名字长度16、输出容量12；SDK
把参数交给syscall封装0x86b00，调用号-95。审计停在封装入口，未执行其中
SVC #0x1400。该属性不是boot patch版本getter。

另一个负返回点对照从TA 18dc0注入-1：真实包装器会缓存fallback0并设缓存标记。
两个合成已缓存值0/1控制都不访问服务，直接给出缓存结果。缓存只涉及5b588/
5b58c，与boot全局5b4f4不同；没有据此推断实际SPU配置或跳过真实收尾。

上述共9组SDK/TA片段及4组SMC/SVC/循环/修改TZ边界控制通过。开发时主机映射
范围误包含相邻模块、属性名NUL长度断言多一字节，均在执行服务前暴露并修正，
整套最终退出0。没有为通过控制扩大服务执行范围。

## UEFI App 句柄与清理的实际生产流程

M3SmciDiagnostic.inc只执行一次loadFromBuffer，所得App按值传给GetVersion、
SmciConfigureRecovery和FnuRunRecovery。FnuRunRecovery把同一App传给FseInitialize
及FkmInitialize；FseExchange还检查每次报文对象等于绑定的C->App。
当前恢复候选没有在configure与begin之间release或reload。

新增test_fuxi_m3_session_lifecycle.py在临时目录给既有主机集成测试增加monitor
观察器，不改动既有测试或生产文件，保留原有所有断言。它在真实生产流程提交
前观察对象/命令，检查一次load、同App、版本→configure→恢复顺序、release后无
新App请求，以及隔离或未清理批次不release/delete。两个日期各27个场景通过，
合计54个场景、52条批次轨迹（每组一个文件准备失败不发起批次）。使用ASan/UBSan。
全部filesystem/monitor为合成；这不替代实机安全世界轨迹或解密验证。

隔离时mRecoveryRetained跳到Done，跳过app/loader/env release和桥删除；此前
模拟-62场景同样验证release=delete=0。随后SmciReleaseTaImage仍会清掉**CPU私有
的原始TA输入镜像**，这不是释放远端App或隔离共享页；两者归属不能混同。

历史lookup返回对象错误2只能证明请求被拒绝；不能证明应用不存在。当前
loadFromBuffer成功只表明返回了可用对象；其背后是否复用ABL实体、按环境分组、
新建实例或重置全局，尚未由接口名、App=4等短句柄或这些主机模拟证明。
因此既不能把boot202607回退片段当作已继承状态，也不能断言新对象必为boot0。

## 复现与后续门槛

```sh
/Users/zhuxiaocheng/.pyenv/versions/3.12.3/bin/python3 tools/audit_fuxi_m3_sdk_lifecycle.py \
  --partition out/m3-date-support-v1/keymaster-partition-verified.img \
  --tz out/m3-boot-provenance-audit-v1/rom-tz.img \
  --identity docs/evidence/fuxi-m3-firmware-identity-20261030.json \
  --output out/m3-sdk-lifecycle-audit-v1
docker exec -w /work/ramdisk-test/uefi-twrp-data unixnu-fuxi-build-arm64 \
  /work/build-support/venv-arm64/bin/python3 tools/test_fuxi_m3_session_lifecycle.py \
  --edk2 /work/uefi-fuxi/Mu_Basecore \
  --report out/m3-sdk-lifecycle-audit-v1/session-tests.json
```

规范证据：[SDK边界](evidence/fuxi-m3-sdk-lifecycle-20261030.json)、
[生产会话模拟](evidence/fuxi-m3-session-lifecycle-tests-20261030.json)。汇编/REVIEW在
忽略的out/m3-sdk-lifecycle-audit-v1，不提交厂商二进制。

已排除当前源码/模拟中的configure→恢复换句柄或隔离后卸载问题。剩余关键门槛
是安全世界加载器的实例关联和真实初始化服务状态，或等价的同轮公开字段证据。
在这些边界未清楚前，不直接设置boot、重发208/setVersion、升级原键或放宽隔离。

后续[当前loader核验](fuxi-m3-deployed-loader-20261030.md)定位到UID122实际invoke：
lookup需要额外架构BO4/count1011；loadFromBuffer确有缓存复用路径。已取得静态/
私有缓存控制依据，真实设备缓存与ABL实例关联仍未证明，不再仅停留于接口名推断。
