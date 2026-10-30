# M3 启动字段来源与 SDK 参考补齐（2026-10-30）

本轮继续离线核验，取得两项新证据：历史 ABL 有明确的208请求构造链，旧A/B
镜像头在该回退路径下均得到boot202607；本地ROM则补出了此前缺失的三个SDK
初始化函数。**实际-62返回点仍未锁定。** 当前slot_a的ABL/TZ身份、实际字段来源
选择、TA实例延续及SDK服务返回值没有捕获，不把片段值倒填为实机槽值。
本轮未访问手机、修改生产固件、构建启动候选或发送安全命令，M3/M4/M5未通过。

## 固定 ABL 与镜像绑定

| 输入 | SHA256 / 关联 |
| --- | --- |
| 2026-10-22只读保存的abl_b，8388608字节 | `78595f9a5fbaba528b894fa7f3991db37fe1bcd03be3036e5cb3c254405655f3` |
| LinuxLoader PE，1142784字节 | `b5ccae26a30febeb6c303dde9c141eee2241f0046c27e5918667f1d7d316e954` |
| 固定TA，524288字节 | `2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6` |
| A候选 | `169e7401d2fa3fcce8347f50232b253c11bf884773b474fb2365b3b52185e44b` |
| B候选 | `81e1abd43ec63d27abd970be69943557d388b61e72ce6274f1684b9a977474f5` |

不仅校验既有PE哈希，还从ABL的0x1060 GUID-defined section有界LZMA解压
1142984字节，验证其中偏移184的PE逐字节一致。捕获来源为历史
firmware-capture-manifest.json；slot_b历史证据不替代当前slot_a身份。

直接BL机器码确认2dc8c→717e8；该链通过共享跳板71ea0调用QSEECom协议。
71724为0x200版本查询，71a0c为先前ROT发送点，71a70为后续boot-state发送点。
本轮不执行上述协议入口。

## ABL 的两类字段来源

固定二进制在2d7ac..2d914查找/处理com.android.build.boot.os_version与
com.android.build.boot.security_patch两个vbmeta属性，另有2da38镜像头回退。
本轮不执行AVB、属性查找或来源选择：日期从**成功查找后的解析片段**进入，
镜像头从**已决定回退的片段**进入。只证明路径和字段转换，不能证明临时启动
选择了哪一路、哪份镜像或vbmeta。

两个旧候选都是boot v3，头os_version_raw=0x220001a7，即OS17.0.0、**2026-07**。
A/B改变后续configure日期，镜像头保持相同，不能称为独立改变boot上下文的对照。
本轮没有修改镜像头或提出改日期候选。

真实回退片段得到packed OS=17<<14、packed patch=0x1a7。随后真实ABL构造片段
71a20..71a70在公开合成记录上形成请求；仅对固定32字节memcpy作有界模型：

```text
请求头4个LE整数：0x208 / 0 / 16 / 48
请求总长度64，响应容量4
记录起点请求+16，记录+0x28为packed OS，+0x2c为packed patch
```

合成颜色值、全零合成摘要不是实际启动状态。先前ROT的成功分支没有执行或
伪造返回成功；片段在71a70发送前停止，私有请求没有发给设备。

## TA 边界解析与日期转换

此前未覆盖的31f10现已核验：它检查输入偏移、剩余长度与最小游标，形成记录
指针并推进游标，唯一直接调用目标为日志入口20。**它是边界解析，不是认证函数。**
该判断限于固定函数，不推断dispatcher或平台服务没有授权检查。

审计从bc00进入，跳过bb7c..bbfc的平台查询和一次性门控，按映像初始化栈保护值，
运行真实31f10，再继续日期/OS转换。只建模目标5ba7c、源请求+16、长度48的
精确memcpy，在bdf8调用404b4前停止。此时标记和boot已写，仍不是完整操作成功。
404b4还调用18d4c，可能继续40f50；这些服务没有执行。

| 公开合成输入来源 | 局部转换值 |
| --- | --- |
| 旧A镜像头回退 | OS170000、boot202607 |
| 旧B镜像头回退 | OS170000、boot202607 |
| 日期属性片段2026-10-05 | boot20261005 |
| 日期属性片段2026-10-31 | boot20261031 |
| 日期属性片段2000-01-01 | boot20000101 |

带日值只是此属性片段结果。实际公开blob的boot202610为月粒度，不能据此猜定
实际来源；前轮后解析片段已验证日字段0对应月粒度。还不能推断ABL中的状态
延续到了UEFI加载的TA实例。

## 本地 ROM 补出的 SDK 参考

输入为既有PixelOS_fuxi-17.0-20261024-0342.zip，不下载或安装依赖。只读固定
payload头与199029字节manifest，后者SHA256为
`cc48764e4df5e8941f09b7a90623c95aff3b52481df6bdac705b94518795b146`。
仅解压manifest中的Keymaster/TZ小操作，校验各段压缩哈希、范围、输出长度及
完整输出哈希，不提取vendor或用户数据。

| 参考 | 已验证 |
| --- | --- |
| Keymaster，409600字节 | `61b45016eba26d3e9c4e1dcca5238420847a49618cd8030591f04971f91da480`；与固定TA前409600字节完全相同，余114688字节全零 |
| TZ，3973120字节 | `d4b8afbe3a8b3468a0f4f740059ab9aed0a8ef803af4f1f58b164ce1c460d418` |

分区完整哈希不同源于零填充，不能据此判定Keymaster版本不同。但**Keymaster
匹配不证明TZ/SDK与当前手机匹配**。内部哈希也不是发行签名或真实性验证。
manifest没有独立cmnlib分区名，不等于没有嵌入库。

TZ内置模块相对基址0xd860f000，动态表0xd8698000。通过PT_LOAD映射，核验SysV
hash的468项符号及字符串表，确认三项均为已定义函数，不只是导入或字符串：

| 符号 | 模块相对地址 | TZ ELF虚拟地址 | 大小 |
| --- | --- | --- | --- |
| cmnlib_init | 0x3178 | 0xd8612178 | 0x2a4 |
| GPAppLib_init | 0x1071c | 0xd861f71c | 0x200 |
| GPAppLib_appInit | 0x1091c | 0xd861f91c | 0x84 |

入口含TLS（TPIDRRO_EL0）状态、分配与对象服务交互，不能当空函数。比如appInit
在0xd861f958直接调用对象服务跳板0xd86109f0，再处理服务输出。本轮只归档代码/
哈希/边界，没有执行SDK、服务或替代成功，未断言它们不影响boot上下文。

## 检查与复现

启动字段审计29组控制通过：2个候选链、3个日期链、5个坏日期拒绝、5个头控制、
8个TA边界控制、6个服务停止/修改输入拒绝。覆盖短头(-29)、截断/越界/偏移落在
头内/超长/短记录(-21)，以及合法输入和地址变化；拒绝时boot与标记均未写。
开发中负对照暴露旧零补丁诊断跳转和合成片段栈保护初始化两项宿主框架遗漏，
修正后完整运行退出0，未扩大到安全服务。SDK静态审计另验证包内范围/哈希、
TA字节一致及三个已定义函数。旧A/B各91源码绑定不变。

```sh
/Users/zhuxiaocheng/.pyenv/versions/3.12.3/bin/python3 tools/audit_fuxi_m3_boot_provenance.py \
  --abl /Volumes/External/VSCode/UniXNU/boot-tests/2026-10-22-stage-markers/private/abl_b.img \
  --linuxloader /Volumes/External/VSCode/UniXNU/boot-tests/2026-10-22-stage-markers/private/LinuxLoader.efi \
  --partition out/m3-date-support-v1/keymaster-partition-verified.img \
  --candidate-a out/m3-configure-context-a-v1/Mu-fuxi-usb-ram.img \
  --candidate-b out/m3-configure-context-b-v1/Mu-fuxi-usb-ram.img \
  --output out/m3-boot-provenance-audit-v1
python3 tools/audit_fuxi_m3_sdk_reference.py \
  --archive /Users/zhuxiaocheng/Downloads/PixelOS_fuxi-17.0-20261024-0342.zip \
  --partition out/m3-date-support-v1/keymaster-partition-verified.img \
  --output out/m3-boot-provenance-audit-v1
```

第一项用既有Unicorn/Python在沙箱外私有内存运行，第二项只静态解析。厂商二进制
与汇编留在忽略的out/m3-boot-provenance-audit-v1，不入库。规范证据：
[字段链](evidence/fuxi-m3-boot-provenance-20261030.json)、
[SDK参考](evidence/fuxi-m3-sdk-reference-20261030.json)。

下一门槛是绑定当前手机ABL/TZ身份，再核对SDK对象服务与TA实例加载/卸载链。
同轮来源/实例证据补齐后才能决定新的公开字段诊断候选；不能直接设置boot槽、
拼造启动状态、重发208/setVersion或放宽隔离代替证据。

## 后续实机身份补充

[当前固件身份核验](fuxi-m3-firmware-identity-20261030.md)取得TWRP两轮稳定摘要：
当前slot_a的TZ与ROM补零后匹配；ABL A不同于历史ABL B，但同一ROM中找到了
与ABL A全分区哈希匹配的版本。已独立提取新PE并用当前地址重核验，明确进入
头回退片段后旧A/B仍局部得到boot202607。现已补齐当前slot A分区版本依据，
但实际字段来源、SDK服务返回、TA实例延续和真实-62返回PC仍未证明。
