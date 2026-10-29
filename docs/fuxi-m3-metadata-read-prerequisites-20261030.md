# M3：从一次 metadata 明文读取倒推依赖（2026-10-30）

本轮为 **B 线离线审计与可执行验证**；没有新固件、SMC、设备操作、真实密钥输入或
明文读取。M3 仍未通过。当前最新硬件基线为 `m3-date-support-v1` 的查询与释放闭环；
不能把本文的主机验证升级为密钥转换、装钥或解密成功。

交付工具：`tools/audit_fuxi_m3_metadata_read.py` 与
`tools/test_fuxi_m3_metadata_read.py`。报告、汇编与检查退出码在独立目录
`out/m3-metadata-read-audit-20261030/`，不改写旧候选。

## 结论与下一项工作

**第一项尚未接通的依赖是 storage key 的恢复。** 已读到的
`/vold/metadata_encryption/key/keymaster_key_blob` 不能直接当作 convert 输入。
需要先独立实现并验证现存密钥的只读恢复路径，再进行 storage-key 转换。
该恢复过程本身可能需要 KeyMint 初始化；不能从下面 FBE 导出分支的性质推断
整个流程都能省略 configure，也没有证据支持现在先发送 `0x2116`。

目标链保持：

```text
/metadata 现存 key 目录（只读）
  → 恢复/认证解密 storage key（拒绝生成、更新与持久化）
  → convert/export 得到受限、不透明的临时 storage export
  → 本次启动中 HWKM/ICE 就绪 + 自有槽位装钥
  → 经核实的 DM 映射/DUN → UFS 实际提交位置的一次 4096 字节 READ
  → 与可比较状态的明文摘要一致 → 停队列与确认清钥
```

这只是 M3 的 metadata 层；M4 的 fscrypt、M5 的完整 RAM 对象交接仍独立验收。

## 固定输入与证据等级

| 输入 | SHA256 |
|---|---|
| 本机 `keymaster_a`，524288 字节 | `2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6` |
| TWRP `system/bin/recovery` | `9aa603b1b2851df9c773c153f7df4520b7c634be0c15bc55f43c2fb83b82e4b0` |
| `hwkm.ko` | `abc7af9de664efa1ca2ddda980acf2c58021da9180974153818ecc29dc2a450a` |
| `crypto-qti-hwkm.ko` | `be67c86de45b02bfc9e00089c6b49899c1d2579e7db2860e684b186cf22e866d` |
| `ufshcd-crypto-qti.ko` | `02ed3dd34b22ecde458bef3644906ae42b4192be039dbc1dc12e7f0abdbca538` |
| `qcom-scm.ko` | `8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5` |

recovery/模块取自本地旧 TWRP 展开档；与 A17 的关键文件相同性依据
[已有 A17 静态比较](fuxi-twrp-a17-static-20261027.md)。本轮不依赖旧 TWRP
能解密当前系统的假设。这六个固定二进制的检查均在主机进行；厂商内容不入 Git。

## 1. 恢复密钥与导出密钥是两段操作

固定 recovery 的地址及数据流：

| 位置 | 本轮核对的事实 |
|---|---|
| `0x25336c` | 调用 `retrieveOrGenerateKey`，输出参数 x4 为 `sp+0x30` |
| `0x25338c..0x2533b0` | 将同一向量作为 x2 传给 `0x253d78` |
| `0x253dbc/0x253e04..0x253e08` | 保存 x2 为 x24，再作为 x0 调用 `exportWrappedStorageKey` |
| `0x24f494` | 现存目录分支调用 `retrieveKey`；另有 generate/store 分支，UEFI 不能移植其写入行为 |
| `0x24b1a8` | `retrieveKey` 调用 `readSecdiscardable` |
| `0x24b3f4..0x24b424` | 拼入 VA `0x42874` 的 `encrypted_key` 文件名并读取 |
| `0x24b558` | Keymaster 分支调用匿名解密函数 `0x24ba0c`；另有软件 AES-GCM 分支，本轮未确认设备实际走哪支 |
| `0x24c984..0x24cb6c` | 使用 VA `0x2c9dd` 的 `keymaster_key_blob` 名称，读取后调用 `Keymaster::begin` |
| `0x24bd34` | 匿名解密函数调用 `KeymasterOperation::updateCompletely` |
| `0x24cbb8` | 相邻恢复辅助流程存在 `writeStringToFile`，不能因上层名为 retrieve 就视为全程只读 |
| `0x2484a8` | `exportWrappedStorageKey` 另调 `Keymaster::exportKey` |

匿名函数的 objdump 标签是最近的动态符号，不能把 `retrieveKey+0xb18` 等标签当函数名。
这里用固定输入、指令地址、字符串和参数流共同绑定，不宣称完整恢复算法已经还原。
特别是应用绑定、认证参数、stretching/其他文件需求、begin/update/finish 的精确协议、
可能的升级分支与安全世界服务副作用仍须继续核对。**不能把 208 字节 blob 的长度或
先前哈希匹配当作 storage key 身份证明。**

## 2. configure 与 convert 的真实关系：局部分支已验证，全链前提未证

固定 TA 的 convert 表项处理函数 `0x29df0` 调用 `0x36620`；其 blob 解包链为
`0x310a8 → 0x31040 → 0x30d9c`，解包后调用版本检查 `0x98c0`。

本轮在 Unicorn 中执行真实指令与真实 CBOR 解码器，仅输入合成授权 map：

- 存储表示中的标签 `0x700002d2` 设置内部结构 `+0x1d4`；普通对照标签不设置。
  另在请求参数处理 `0x32d14..0x32d38` 核对厂商标签 `0x70003f49`、同一字段与
  VA `0x55846` 的 `KM_TAG_FBE_ICE - using FBE ICE` 字符串；两种编码域不混用。
- `0x98c0` 先检查 `+0x1d4`；非零时直接返回 0，不访问 OS/补丁状态槽。
- 该字段为零时：过旧版本返回 -62；版本足够新时，真实 getter 会读取 OS、OS patch、
  boot patch、vendor patch，匹配样本返回 0，各字段不匹配的对照均返回 -62。
- convert 的后续导出函数 `0x1ffc` 要求该字段非零，否则返回 -17；非零时到达
  `0x43a30`，本轮 **在入口停止模拟**，没有模拟成功导出，也没有调用安全服务。

另有两项负对照：未知相邻标签被该 parser 忽略而不设置 FBE 字段，不能猜测它必然报错；
缺少第二个 map 的损坏输入可以先设置字段，随后返回 -33，故部分字段更新不等于解析成功。

这缩小了“必须先 configure 才能做 convert”的论断，但 **没有**证明当前实际 storage key
含该属性、通过认证、导出成功或可装入 ICE。合成 map 不是真实/认证 key blob，不能替换
设备输入、改标签或在生产代码中设置该字段来绕过验证。解封包装密钥的路径也可能属于
非 FBE 分支，因此不能推广成“整个 M3 无需 configure”。

模拟将 PAC 控制流模型化、抑制日志；没有为 KeyMint/Gatekeeper 返回伪造成功。
除日志/PAC 适配外，本轮 parser、版本检查和 getter 使用固定 TA 指令，报告明确
区分局部函数返回与未执行的导出服务。

## 3. HWKM、SCM 与 UFS 的实际缺口

| 环节 | 已有证据 | 在一次明文 READ 前仍需补齐 |
|---|---|---|
| HWKM | 固定 `hwkm.ko:qti_hwkm_init` 在基址 `+0x1004` 检查 bit9/7/2/1/0，初始化含多次寄存器写与命令处理；`crypto_qti_program_key` 检查自己的初始化标志 | 本机基址、时钟/复位与初始状态；UEFI 本轮初始化及 readback；不能借用 Linux 私有布尔值 |
| 槽位 | logical slot、SCM slot=`logical*2`、capability index 属于不同域 | 槽范围、本次归属、装钥状态与清理时机；未知终态隔离 |
| 清钥 | 固定 invalidate 在未初始化时可直接返回 0，不发 clear | 队列停稳后的实际 SCM clear 与终态；单纯 evict=0 不足 |
| 六参 SCM | set 的 arginfo=`0x86`；扩展区 56 字节，SMC64 的 x5 指向 args[3..9] 存放区；当前通用桥构造器仅支持四参 | 独立注册/缓存/释放扩展区和 key 区、SCM 中断/未知状态与资源保留；不能把第5/6参直接放 x6/x7 |
| DM/DUN | `FdmPlanMetadataRead` 已有 4 KiB、wrappedkey_v0、iv_large_sectors 的限界算术；既有 TWRP 映射快照可作计算对照 | 重新绑定实际映射和可比较原始/明文状态；不是裸 userdata LBA=所有层的 DUN |
| UFS 提交 | `FnuSubmit` 在 cache/doorbell 前调用 `FnuFillUtrd`，后者清零 words1/3 且不设 crypto-enable | crypto context 必须传到实际构建/提交位置；外围预填会丢失；现有合成布局不足以启用实机 |
| 对照/停机 | 已有 TWRP 首块摘要来自 rw 挂载会话；历史 SMMU FSR=0x400 未解释 | 对照状态可比较、完成状态可信、UFS 停机/清钥与 DMA 归属齐备，才能形成 M3 证据 |

本轮没有给 UFS 填未经验证的加密位、扩大通用 SCM 调用接口或改变默认开关。
在密钥恢复身份与后续清理未成立时，这些接线不能成为可启动的解密候选。

## 4. 下一候选的准入范围

下一项具体实施应先覆盖 **现存 metadata key 的只读恢复契约**：核对目录文件角色、
认证/应用绑定、正常 begin/update/finish、失败时 abort/清理；明确得到的恢复结果才是
wrapped storage key，再接 convert。所有材料只留在有归属的内存，禁止内容/前缀日志、
主机导出或落盘。缺失文件、需要升级/生成/持久化或未知返回均停止，不能套用 recovery
的写文件补救分支。现有 C1 诊断的 blob-prefix 输出也不能带进未来恢复/转换候选。

configure 只在上述实际恢复或转换路径证明需要时纳入最小序列；本轮不发送。
这项准入定义并不证明已得到可上机候选，也不准许忽略既有非零返回保护。

## 5. 复现与验证

以下相对路径在 `ramdisk-test/uefi-twrp-data` 下。Python 环境需安装 Unicorn；
本机已存在的 `../../build-support/venv-apfs-static/bin/python` 可用。

```sh
PYTHONDONTWRITEBYTECODE=1 ../../build-support/venv-apfs-static/bin/python \
  tools/audit_fuxi_m3_metadata_read.py \
  --partition out/m3-date-support-v1/keymaster-partition-verified.img \
  --modules ../../boot-tests/2026-10-25-twrp-skkk-data-readonly-analysis/ramdisk-files/vendor/lib/modules/1.1 \
  --recovery ../../boot-tests/2026-10-25-twrp-skkk-data-readonly-analysis/ramdisk-files/system/bin/recovery \
  --output out/m3-metadata-read-audit-20261030 \
  --objdump /opt/homebrew/opt/llvm/bin/llvm-objdump

PYTHONDONTWRITEBYTECODE=1 ../../build-support/venv-apfs-static/bin/python \
  tools/test_fuxi_m3_metadata_read.py \
  --partition out/m3-date-support-v1/keymaster-partition-verified.img \
  --modules ../../boot-tests/2026-10-25-twrp-skkk-data-readonly-analysis/ramdisk-files/vendor/lib/modules/1.1 \
  --recovery ../../boot-tests/2026-10-25-twrp-skkk-data-readonly-analysis/ramdisk-files/system/bin/recovery \
  --report out/m3-metadata-read-audit-20261030/tests.json
```

审计、6 个固定输入逐一篡改拒绝、13 项反例/执行边界测试通过；后者包含版本不匹配、
旧版本、损坏/未知授权、导出前停止、合成 SMC 拒绝与自循环指令数上限。
既有生产 DUN 规划器和 UFS 核心 ASan/UBSan 检查见本轮 REVIEW/退出码报告。
没有新固件镜像，交付镜像资格/上机检查不适用；没有模块源码修改，不以旧模块构建
或旧照片充当本轮解密结果。

macOS 沙箱内 Unicorn 首次 `uc_mem_map` 触发主机 SIGILL，用户报告栈为
`init_cache_info`、指令 `0xd53b0028`（读取 CTR_EL0）；当时没有执行 TA 指令。
同一主机环境在沙箱外运行后通过；这只是可复现运行条件，不是修复了 Unicorn。
模拟开发时的 map 缺项/版本样本与未知 tag 错误预期也曾失败，修正后重跑；失败事实
保留在 REVIEW，不删改历史候选或真实返回策略。
