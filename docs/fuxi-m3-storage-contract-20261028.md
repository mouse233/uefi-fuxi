# M3 storage 后半段契约静态推进 — 2026-10-28

本轮在 HLOS 桥闭环实机成功后并行开展；只反汇编本地固定库/模块，不执行厂商代码、TA、SMC、设备命令或加密 I/O，不读取任何实际 key/blob 内容。没有修改生产 UEFI。
交付 tools/audit_fuxi_m3_storage_contract.py、tools/test_fuxi_m3_storage_contract.py，证据位于 out/m3-static-advance-v1/storage。

## 固定输入

| 文件 | SHA256 |
|---|---|
| libqtikeymint.so | 657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb |
| qcom-scm.ko | 8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5 |
| crypto-qti-hwkm.ko | be67c86de45b02bfc9e00089c6b49899c1d2579e7db2860e684b186cf22e866d |
| ufshcd-crypto-qti.ko | 02ed3dd34b22ecde458bef3644906ae42b4192be039dbc1dc12e7f0abdbca538 |
| crypto-qti-common.ko | 3ee5088ac15e581aff71ddb0f50c8987a21d10b2ffec7f7468e8108ebe4f5242 |

## ConvertStorageKey 输出格式的新证据

libqtikeymint.so 的 convert 命令 0x311d 先前已绑定。其返回调用 deserializeClientExpKey：

- @35dac..35e70：初始化 QCBOR 解码，首元素检查枚举 5。
- @35ecc..35ef4：标签类型允许枚举 2/3，并检查标签整数为 0x24（36）。
- @35f08..35f20：值类型检查枚举 6，保存指针和长度；@35f2c..35f34 调用 Finish。
- @35fa4..35ff0：只在解码结束成功后分配该长度，km_memscpy 后把指针和长度写入输出结构。

官方 QCBOR 头的公开枚举为 MAP=5、INT64=2、UINT64=3、BYTE_STRING=6：
[qcbor_decode.h](https://github.com/laurencelundblade/QCBOR/blob/master/inc/qcbor/qcbor_decode.h)，读取时 Git blob f873eedc761f1ace17b7d82c9c0cd7cd9159533e。它只是枚举语义的公开交叉证据，不证明本机库内 QCBOR 精确版本。
因此固定调用点支持“返回 map 的整数标签36对应 bstr”的解释；尚未执行厂商解码器或 TA，不宣称逐字节等价、全格式解析或任何固定输出长度。
请求侧标签23与返回侧标签36不能混用。成功输出应保持为不透明 storage export；这些指令不证明它是可直接使用的64字节 AES-XTS裸密钥。

新增无秘密 host 模型仅校验保守子集：LE32 status/length 外壳后跟单项 definite CBOR map{36:bstr}，返回长度和固定元数据，不返回 payload、hex或摘要。它不是可接手机的完整厂商解析器，不能假定真TA仅有这一子集。
26个合成向量覆盖大小界限、状态/长度、错标签/类型、空值、截断、尾随数据、indefinite/reserved长度等；所有输入均为合成重复字节，并检查模型无stdout、无bytes输出。

## ICE/HWKM 的三个索引和真实约束

固定 crypto_qti_program_key：

1. @270..278 从key结构+0x14读取长度，<=32时走拒绝分支。**大于32只是这条固定路径的必要条件**；不能把任意>32输入判为合法wrapped key，也不能由此推断TA输出长度。
2. @2b0..2c4：先把 ICE base + 0x4040 + logical_slot*0x80 对应配置字清零，随后 dsb st。
3. @2ec/@300：SCM key slot 是 logical_slot*2；@308..310 的末三参数均0。它与配置寄存器偏移中的 logical_slot、UFS capability index 是不同命名域。
4. @314调用set；成功后才写 enable bit31 + 数据单元掩码低字节 + capability index高字节 @334..348。
5. ufshcd-crypto-qti.ko @318 用 data_unit_bytes>>9 得到512扇区单位的掩码；@350..37c按算法、key-size代码和支持掩码共同选 capability。4096对应8，capability index3本身不是keyslot3的证明。

qcom_scm_config_set_ice_key @5518..55b4 的参数信息是0x86、六个参数、owner2/service10/cmd5、standard type2；参数数>=5进入__scm_smc_call额外缓冲路径。
固定 @89e8..8af0 对扩展区分配56字节，并从desc.args[3...]填充；在SMC64分支，x5必须指向扩展参数区，不是直接把第4参数塞x5、第5/6参数塞x6/x7。
当前4参桥成功不能替代六参ICE调用的扩展共享区注册、缓存、生命周期和终态验证。公开通用五参set-key布局不可套用本机六参包装。

## 清钥和日志的具体陷阱

crypto_qti_invalidate_key @4f4..554 检查私有HWKM初始化标志；未初始化时不发SCM而直接返回0。已初始化分支 @500..508 才发clear(logical_slot*2,0)。
crypto-qti-common.ko @9fc..a50仅包装该函数并传播返回；UFS层还包了hold/release。因此“evict返回0”不独立证明真正清掉硬件密钥。
未来验收至少要绑定自己拥有的逻辑slot、先前真实装钥成功状态、队列停稳、实际SCM clear调用及其返回；未知终态隔离槽位和相关内存，不能回收给下一次使用。

原厂program失败分支 @3cc..408 会从key结构+0x18逐字节取数据并调用_printk，最多到0x80字节。后续独立UEFI实现必须排除这段具体的payload dump行为，错误日志只含阶段/返回值/脱敏长度等必要元数据。
本轮只检查这些反汇编指令，没有读取真实key内容；无秘密模型测试亦禁止返回/打印payload。

## DUN 与 UFS 接入仍缺少的部分

现有 FdmPlanMetadataRead 的边界保护有效：仅接受已核验的AES-256-XTS/wrappedkey_v0/4096/iv_large_sectors映射，target/device/IV均按512扇区计算，DUN=(iv_offset+relative)/8，disk LBA=partition_first+(device_start+relative)/8。
已有TWRP几何快照支持首块LBA0x2f7840、DUN0、末块DUN58739642的算术测试，但跨重启仍须绑定映射及身份；fstab和单块hash不足以重建配置。

UfsCore.c:80的FnuFillUtrd始终把words1/3清零且word0不设crypto-enable；FnuTransfer每次重新调用它。
因此不能在外层先写crypto头再调用现有FnuReadBlocks：该头会被重建覆盖。未来需显式、默认关闭、经类型/所有权验证的crypto context传递到真正提交位置。
现有tools/m3_ufs_crypto_layout.py仅16字节通用合成布局，未与真实keyslot、控制器capability、HWKM、DUN及错误处理接通；也不证明fuxi的最终硬件格式。
PRDT/UCD与SMMU的地址、缓存、poison策略须保持；未知完成时不能为了清钥或复用槽位而擦写仍可能被控制器持有的buffer。

## 必须实机的依赖顺序

1. 在HLOS桥上最小root register/release通过，才能推进受限client-env/loader会话；本报告不构成这些阶段的通过证据。
2. TA版本/配置、storage转换成功且严格有界取得不透明输出。不要依据命令号或CBOR形状推断授权/解密成功。
3. 独立证明HWKM/ICE已就绪、slot范围和所有权，以及六参SCM扩展区的真实调用终态；装钥后必须有可靠清理路径。
4. 最后才允许一次有界metadata crypto读，把真实mapping/DUN/UTRD/slot绑定，校验同一可比较快照的F2FS魔数和脱敏摘要。

到此，继续声称TA转换、装钥、清钥或明文读取成功都必须依赖设备返回；静态审计和合成向量不能替代。

## 复现与结果

在UEFI检出根目录运行：

    python3 tools/audit_fuxi_m3_storage_contract.py --ramdisk out/twrp-a17-analysis/ramdisk --output out/m3-static-advance-v1/storage
    python3 tools/test_fuxi_m3_storage_contract.py --ramdisk out/twrp-a17-analysis/ramdisk --report out/m3-static-advance-v1/storage/tests.json

两条命令退出0。固定五个输入的SHA与关键指令审计通过，五个逐一修改的文件全部拒绝，26个无秘密合成向量通过。
audit.json/tests.json绑定本次独有工具及所引用规划器/UfsCore/合成布局源码。没有新增固件镜像或实机操作。
