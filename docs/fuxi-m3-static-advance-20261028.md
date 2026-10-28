# M3 并行静态推进与实机边界 — 2026-10-28

## 当前证据基线

本轮按用户要求并行分析后续M3，未查询、重启或启动手机，未执行vendor/TA代码。
改动位于UEFI DXE与主机工具；未改DarwinBoot/XNU、Android分区或系统载荷。

已验证硬件事实是显式HLOS桥：标准enable/create/delete，VM count1/VMID3/NS与TZ权限6，
create a0=a1=0、a2返回句柄，delete成功、8KiB释放并PARK。
照片IMG_7171..JPG SHA256 f1898e745c651b22ff7705a964eb59bc711bc54ee18a25c32863f11f00a3e288。
这不证明QTEE对象调用、TA、KeyMint、ICE或解密；SMMU FSR400仍是未解决的观测。

旧零VM桥产生a1=5C/a2=0，不再把5C当句柄。此前root命令0/2的FFFFFFFF80000001
是在未验证桥的基线上取得，不能据其断言HLOS桥上的对象调用必然失败或已经修复。

## 三条离线分析线

| 分析线 | 本轮可核对内容 | 仍需实机或缺少输入的内容 |
| --- | --- | --- |
| root/SMCI | 固定模块op5/count1100、null credentials、12字节头、8字节描述符、in页+20的OO、cmd2/owner0x32/arginfo224与返回分层 | root在HLOS桥上是否返回远端对象，是否要求callback/中断恢复/piggyback，release与delete是否完成 |
| client-env/loader/TA | UID122 loader、lookup优先、loadFromBuffer、sendCommand消息、KeyMint命令与初始化次序；可做无秘密布局与边界模型 | 真实对象权限、TA输入版本与完整分片、固件返回；当前ramdisk未恢复keymaster分片 |
| wrapped key/ICE/UFS | convert请求与响应解析、slot映射/配置、长参数、清钥分支及已验证DM几何；可做无秘密边界模型 | 实际转换输出的生命周期、slot所有权/HWKM就绪、装钥和确认清钥、有界加密READ的同状态明文对照 |

固定本机ELF和模块优先于公开参考；公开源码需绑定版本，合成模型通过不等于vendor逐字节等价。
独立专题、审计脚本、报告与来源哈希一并归档；未修改他人未跟踪的A17交叉分析稿。

## 主线已准备的最小C2

候选out/m3-smci-root-hlos-v3，object-cmd2 72000602/arginfo224，
采用已验证的HLOS桥参数，输入输出分别为同一8KiB连续区的前后4KiB。
仅root registerWithCredentials(null) → 验证远端对象 → release → bridge delete。
补全bridge实参与a0..a3日志，记录CurrentEL/DAIF但不改异常级或中断状态。

候选仍只接受明确的简单终态：全零返回tuple、头/描述符完整、合法远端handle、空out页。
这是严格接受子集，不声称真实ABI只允许空out；合法callback/piggyback仍可能触发保留驻留。
未知创建、对象返回、release或delete状态均停止后续调用并保留资源，不猜句柄、不自动重试。
没有TA、blob/key读取、KeyMint转换、ICE写入、加密READ、接收器或OS handoff。

生产代码矩阵为2种invoke入口×2种桥配置×37场景，共148个ASan/UBSan向量；
含实测错误、服务错误、64位桥句柄与未知状态不擦写/free。桥独立24向量、固定模块/DTB审计及16项完整交付检查通过。
未上机。镜像SHA、源码commit和检查绑定以候选REVIEW与committed-source-bindings为准。

## 后续缓冲容量不能沿用C2

固定参考sendCommand封送模型把请求与响应区间同时作为BI/BO内联到in_msg。
40KiB的QSEECom用户缓冲不等于40KiB SMCI消息；BI4/BO2/OI4需要10个描述符，
头与描述符先对齐到96字节，典型send=8/response=40952时模型wire长度为82024字节，
再按4KiB对齐为86016字节（21页），还需独立callback out_msg。
此为封送语义与边界模型，未执行vendor代码；8KiB候选仅适用于本次C2，不可直接扩展成TA通道。

另有四项后续实现约束：
- lookup成功分支跳过ELF EI_CLASS保存，故不能按keymaster64名称直接填is64；必须另取证。
- convert请求标签23与返回标签36不同；返回bstr仍是不透明storage export，不是裸AES key证明。
- ICE配置寄存器使用逻辑slot，SCM使用slot*2，UFS capability index属于第三个域，不能混用。
- 当前FnuFillUtrd每次重建并清words1/3，外层预填crypto字段会被覆盖；未来必须向实际提交层传显式crypto context。厂商失败分支的key dump也不得移植。

## 后续阶段与验收顺序

1. C2：必须先在HLOS桥上验证root最小闭环。若出现callback/等待/未知tuple，保存全部raw与缓冲描述符，先补该状态机；不得继续open loader。
2. C3：以经验证client-env对象open UID122 loader，再分别release loader/env；此阶段不加载TA、不读metadata blob。可预先验证布局，但真实handle与权限仍待实机。
3. C4：loader/共享对象生命周期成立后先lookup keymaster；若未找到，必须有准确且完整的TA输入才能加载，缺失则停止。之后单独验证getVersion。不能用UID122代替TA标识，也不猜下载固件。
4. C5：协议版本200与OS version/patch配置分开核对，再考虑convert；长期blob和临时exported/wrapped返回均不打印、不落盘。OS绑定和输出格式不能由命令号推定。
5. C6：独立验证HWKM初始化、逻辑slot/SCM slot/配置寄存器与扩展参数桥；装钥前明确所有权和清理。evict返回0可能是未初始化时直接返回，不能据此确认清钥。
6. C7：按已核实DM几何与4KiB DUN执行有界metadata加密READ，以同状态明文SHA/F2FS证据验证；旧TWRP rw快照不是跨重启不变的预期摘要。

metadata加密层成功也不等于fscrypt DE/CE文件可读，更不等于iPadOS完整启动。
本轮停止于C2需要实机回答的第一个问题；后续静态模型不能生成真实对象、运行态授权或本次启动可用的wrapped key。
