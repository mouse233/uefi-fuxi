# M3：实际版本上下文的查询入口核验

2026-10-31，B线 `feat/twrp-data-uefi`；本轮改动为主机离线审计工具与文档，
没有修改固件、构建新镜像或访问手机。承接IMG_7303的同次公开字段/-62证据，
目标是找实际boot/vendor上下文的可观测路径，不把blob公开值当平台实际值。

**已锁定一条boot输出路径：`0x311f / KEYMINT_GET_ROOT_OF_TRUST`，但尚未形成
完整只读实机契约。没有从已检查接口取得vendor有效槽或实际selector查询。**
这不是所有可能命令/间接调用路径均不存在的证明；也没有读到手机上的boot值。

## 固定输入与命令身份

固定TA分区524288字节，SHA256
`2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6`。
匹配TWRP `libqtikeymint.so` SHA256
`657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb`。

审计保留0x5a5e0起89项表的顺序、flags与重复项（86个不同命令），而非用dict丢掉
重复表项。私有模拟中只执行固定命令名函数d01c，返回值必须指向映像静态字符串。
八组重点身份同时绑定表项handler与实际名称：

| 命令 | handler | 实际名称 / 本轮判断 |
|---|---|---|
| 0x200 | ddf4 | GET_VERSION；协议四整数，不读实际boot/vendor |
| 0x207 | deec | SET_VERSION；df6c等有槽写入，不能当只读版本查询 |
| 0x208 | bb7c | SET_BOOT_STATE；既有状态写入路径，不作为本轮查询 |
| 0x211 | c3a8 | KEYMASTER_SET_VBH；c458把输入复制至5b500全局，不能当查询 |
| 0x214 | 2fe14 | KEYMASTER_PROVISION_ATTEST_KEY_NEW；非查询候选 |
| 0x218 | c038 | FBE_SET_SEED；非boot上下文查询 |
| 0x311e | 3dbec | KEYMINT_GENERATE_CSR；不是RootOfTrustChallenge |
| 0x311f | 31a68 | KEYMINT_GET_ROOT_OF_TRUST；有boot输出，但完整契约未闭合 |

名称用来核对身份，不单凭GET字样推断无副作用。flags=1表明311f仍受既有
configured门控，不能作为未初始化实例的通用状态读取。厂商AIDL
getRootOfTrustChallenge（1ba18）直接以-100构造服务错误，没有在此发出TA查询；
不得因它未实现而把311e当后备挑战接口。

## boot确实进入响应编码参数

真实直接边 `31c44 BL b850`，后续 `31c48 MOV w4,w0`，`31c5c BL 47fd8`：
内部boot getter读取独立全局5b4f4，返回值成为整数编码器参数。枚举固定映像全部
直接B/BL得到boot getter八个调用点，包括31c44；vendor getter另有八个直接调用点，
本段31a68..31f10没有直接调用b940。**这只是直接调用枚举，不排除内联/间接读取；
不能据此声称311f在所有层都绝不会接触vendor，或其他接口均不存在。**

五组私有公开数值0、202607、202610、20261005、0xffffffff注入模拟内存的boot槽，
只执行31c44至31c5c之前：实际getter返回值与编码参数逐组相等，禁止所有内存写，
均在进入编码器之前停下。没有执行完整311f、平台初始化、真实记录/密钥、MAC、
认证或服务调用。它证明数据流，不证明这些数值是合法完整响应或手机实际值。

selector继续绑定既有ELF RELATIVE项5a308→4c544，映像RX常量为0。vendor getter
经这个指针索引槽，而boot不经它。映像默认值与片段控制不构成手机运行态回读，
不能据此声称真实selector=0或完整SDK初始化后的boot=0。

## 请求侧与前置条件

匹配HAL在32a9c选择311f，调用serializeGetRootOfTrust（3a68c）；3a70c设置标签4，
3a71c调用AddBytes。AIDL getRootOfTrust签名为16字节array，TA39a88解析器读取
map里的标签4字节串；本轮只在私有内存运行该公开解析器。

| 合成输入 | 解析返回 / 借用长度 |
|---|---|
| 16字节 | 0 / 16 |
| 0、15、17、130、131字节 | 均0 / 对应长度 |
| 缺标签 | 6 |
| 错误整数类型 | -1 |

解析器借用输入字节串，不能把调用者另一个130字节局部缓冲误当输入复制上限，
也不能声称TA在这一层强制16字节。任何未来独立UEFI查询器应按已核验AIDL子集
显式约束16字节；解析返回0不等于整个方法接受、认证或MAC完成。

真实handler先经过公开parser，再调用bb10：要求5ba58 boot-state标记已设置才
复制32字节；随后b9f4要求5b520初始化标记，再经b9ac复制selector所选VBH。
两个不同前置失败都可返回-30，**不能把-30唯一解释为boot未设置**。
该顺序也说明311f不是无条件读取“未初始化状态”的原始getter。

## 为什么本轮没有直接做查询固件

boot编码之后，真实方法继续经过490b4封装、7fd0和16b80；16bf4通往导入服务PLT
1c0。本轮未执行这些调用，也没有用成功桩替代它们。响应还涉及非版本字节域和
后续加密处理，不能把整个输出当公开日志或随意做摘要。

本轮已补齐命令身份、请求侧标签、孤立公开parser与boot输出片段；还未补齐完整
响应格式/白名单跳过边界、加密服务与回调行为、失败收尾和只读属性。因此没有
新增TA命令发送器、没有复用当前隔离会话、没有按blob值改boot/vendor，未构建
或临时启动新候选。原M3同次观测候选的31项资格/照片与源码绑定保持原样。

下一实现门槛是围绕311f核验完整响应及服务链，形成只读、只输出boot整数的
契约和严格保留规则；vendor有效槽/selector要另找可信观测路径，不能以本条boot
路径替代。无论后续查询返回什么，实际-62返回PC及认证后的结构仍需另证。

## 可复查产物

工具 `tools/audit_fuxi_m3_effective_context.py`：89项命令名、8组身份、16条原始
B/BL边、13个原始指令字、5组编码前boot片段、8组公开parser控制全部通过。
保留全部直接getter调用点、分段汇编和89项表。规范结果
[evidence/fuxi-m3-effective-context-audit-20261031.json](evidence/fuxi-m3-effective-context-audit-20261031.json)，
忽略out中的完整汇编/REVIEW为 `out/m3-effective-context-audit-v1/`。

```sh
/Users/zhuxiaocheng/.pyenv/versions/3.12.3/bin/python3 tools/audit_fuxi_m3_effective_context.py \
  --partition out/m3-date-support-v1/keymaster-partition-verified.img \
  --runtime out/twrp-a17-analysis/ramdisk/vendor/lib64/libqtikeymint.so \
  --output out/m3-effective-context-audit-v1
```

Unicorn在沙箱内JIT退出132，沙箱外私有模拟控制通过，未安装依赖。一次初版
断言误把131字节视为应拒绝；观察到解析器借用输入后修正边界结论并完整重跑。
不将该层宽松解析或局部片段成功升级为完整方法可安全执行。
历史FSR400、真实boot/vendor/selector、-62根因与M3/M4/M5均未通过。
