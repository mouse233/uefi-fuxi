# M3 现存 metadata 密钥恢复核心（2026-10-30）

本轮把 [单块明文读取前置审计](fuxi-m3-metadata-read-prerequisites-20261030.md)
中最靠前的缺口落成独立 UEFI C 库：四个 metadata 文件的有界读取、application ID
构造、现存密钥的 begin/update/finish 状态机。未提供真实 KeyMint/SMCI 后端或生产
调用入口，未读手机密钥、发 SMC、发送 configure、构建启动镜像或上机。**M3 未通过。**

## 固定输入与接口证据

`tools/audit_fuxi_m3_key_recovery.py` 先核对完整 SHA256，再审计本地 ELF 的
file-backed PT_LOAD、重定位及精确反汇编范围，报告在
`out/m3-key-recovery-v1/static/`。它不执行厂商代码。

| 输入 | SHA256 |
| --- | --- |
| A17 recovery | `9aa603b1b2851df9c773c153f7df4520b7c634be0c15bc55f43c2fb83b82e4b0` |
| TWRP libqtikeymint.so | `657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb` |
| 已固定 keymaster TA 分区 | `2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6` |

recovery `0x2487ac` 的 personalized hash 为 SHA512：先输入补零至128字节的
`Android secdiscardable SHA512`，再输入 secdiscardable。`0x24b1c4` 起的恢复流程
把该摘要与认证 secret 拼接，再按绑定状态追加 seed。metadata 调用点 `0x253354`
经 GOT `0x270470` 指向符号 `kEmptyAuthentication`（`0x274380`）；此为 metadata
空认证调用证据，不推广到 CE/口令恢复，也不证明绑定 seed 为空。

GCM 参数：purpose=DECRYPT(1)、BLOCK_MODE=GCM(32)、PADDING=NONE(1)、MAC_LENGTH=128；
APPLICATION_ID tag=`0x90000259`，NONCE tag=`0x900003e9`。`0x24ba40` 的辅助函数
取 encrypted_key 前12字节为 nonce，把余下数据交给 update，再 finish。辅助流程另有
写文件/建目录分支，本库没有移植这些分支。

厂商 begin/update/finish/abort 包含 `0x210f/0x2111/0x2112/0x2113` 与对应 `0x25xx`
选择；固定 TA 命令表只有前一组。构造函数 `0x183f0` 把 SecurityLevel 参数写到
HalDevice+8，begin 还检查 isLegacy。因此**命令存在不等于运行时分支与线格式已验证**。
当前库只定义 CPU 侧 typed callback，不把 C struct 当成 TA 请求。

## 实现范围与归属

生产源码位于 `Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/`：

- `M3KeyRecoveryF2fs.c/.h`：复用现有只读 F2FS，只读
  `/vold/metadata_encryption/key/{version,secdiscardable,keymaster_key_blob,encrypted_key}`
  四个固定普通文件，完整有界 CPU 拷贝；失败清零输出，完成后清理解析工作区。
- `M3Secdiscardable.c`：独立 SHA512 实现。常数按素数立方根/平方根小数部分定义；
  未复制厂商实现。主机用 Python hashlib 独立比对三种输入。
- `M3KeyRecovery.c/.h`：仅接受 version 字节 `1`、存在且恰16KiB的 secdiscardable、
  非空且不超过4096字节的 blob，以及29..4096字节的 encrypted_key。
  调用者须独立核验绑定上下文，显式传入0..64字节 seed；未知绑定在读文件前拒绝。
  `BindingChecked` 是调用者断言，当前没有生产调用者提供该断言。

上述是保守子集：不支持缺失 secdiscardable、其他版本、非空认证、升级、生成或写回。
库不分配内存、不记录秘密、不提供 SMC/存储写接口。文件读取 callback 只能返回 CPU
副本，不能把这些缓冲区注册给 DMA/安全世界。实际传输后端必须自行保留其共享分配。

update 最多16次，要求正向消耗、长度不越界；输出留在私有 Candidate，只有 finish
成功、操作明确关闭、输出长度恰为 encrypted_key 长度减12字节 nonce与16字节 tag后，
`FkrGetRecovered` 才返回指针。所有非零 KeyMint 状态均失败，不升级或重试。
已知失败但操作仍在时最多 abort 一次，确认关闭才清理。未知完成、可疑 handle或
abort 无法确认时进入隔离，拒绝继续调用和 reset，保留库工作区与后端分配。

`FuxiNativeUfsDxe.inf` 收录三个 C 文件；当前没有驱动入口调用此库。
检查实际 AARCH64 对象中函数定义与外部符号白名单，避免仅凭未使用函数被链接器
丢弃后的 EFI 就认定库已验证。两个模块模式仅证明可编译及既有模式边界。

## 本轮验证

独立输出目录 `out/m3-key-recovery-v1/`；主机报告绑定源码 SHA256，构建报告绑定
源码与实际 EFI。最终检查均退出0：

1. `test_fuxi_m3_key_recovery.py`：40项，ASan/UBSan。OpenSSL AES-256-GCM 用合成
   密钥/数据独立验证生产 F2FS → 准备 → callback 核心；tag、密文、nonce 篡改均拒绝。
   覆盖失败清理、未知完成保留、abort失败、长度/消费异常、部分消费上限、文件/绑定
   拒绝与 prepared 上下文损坏。没有真实 TA 或密钥恢复成功证据。
2. 固定输入静态审计：文件名、hash、参数与调用点、空认证重定位、厂商命令分支及
   TA表；新增 SecurityLevel 构造函数范围。此检查不验证实际 wire format。
3. Linux Docker 中 `build_fuxi_data_port.py`：默认与 `--scm-query` 两套 AARCH64
   模块构建。默认两个 EFI 的 SMC 数为0；query 模式 DataProbe 为既有1条 INFO SMC，
   NativeUfs仍为0。本轮未增加 live 安全调用。
4. `check_fuxi_m3_recovery_modules.py`：源码/EFI绑定、SMC数量、三个实际编译对象的
   定义/依赖白名单通过。早期 `modules-no-smc` 保留，最终以 `modules-no-smc-final` 为准。

命令及完整模块 SHA256 见本轮 `REVIEW.md`。未进行设备操作；历史 SMMU FSR400
仍未解释。硬件查询基线仍是 `m3-date-support-v1`，不变成此库的解密证据。

## 下一步验收门槛

先完成**现存密钥恢复的真实后端**：绑定 seed 的本机上下文、实际 security level/
legacy 分支、begin/update/finish/abort 的序列化与响应校验，以及 SMCI 缓冲区和
operation 的归属/关闭证据。拒绝生成、升级和持久化；有证据表明 configure 必需时
才纳入最小序列，不能为继续探测而先发送它。

只有真实恢复成功后，才能把输出交给 convert，再接本轮 HWKM 初始化、自有槽和
清理、六参 SCM、UFS 提交层 crypto context/DUN，最后做一次有界 userdata metadata
块读取并与可比较状态的 TWRP 明文 SHA256 对照。40项主机通过不代替这项 M3 验收，
也不代表 `/data` 文件明文、M4、M5 或免 USB 重传已实现。

后续进展：[AIDL命令链与wire/SMCI后端](fuxi-m3-recovery-backend-20261030.md)。
其中补齐本轮未跟到的AIDL `0x31xx` 路径；本页前述21/25组范围为当时的通用HAL
分支审计，不是完整AIDL命令清单。
