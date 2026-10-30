# M3 configure（0x2116）只读推进，2026-10-29

在 `m3-date-support-v1` 实机 `date-support` 成功之后，继续**只读**核对厂商
configure 路径。不发送 `0x2116`，不改安全世界状态，不宣称可解密 data。

## 固定输入

- 运行时上下文：`out/m3-date-support-v1/android-context-20261029.json`
  - `ro.build.version.release=17`
  - `ro.build.version.security_patch=2026-10-05`
  - `ro.vendor.build.security_patch=2026-10-05`
  - 四项厂商库 SHA 与 PixelOS OTA 一致
- OTA/`runtime` `libqtikeymint.so` SHA256 `368b34db…9e8c52`
- 固定 `keymaster_a` SHA256 `2fc838a8…43cc6`

## HAL（用户态）静态事实

`KeymasterHalDevice::configure`（VA `0x2e3c0`）非 legacy 分支：

1. 仍先调用 `keymint_set_version`（命令 `0x3121` / 整数 200）
2. 再 `KeymasterUtils::init(0x2116, …)`
3. 再 `serializeClientParams`（VA `0x35178`）后 `sendCmd`

因此：手机上的 setVersion 表项缺失（返回 -40）**不会**阻止厂商库继续构造
`0x2116`；这与此前隔离模拟一致。本探针若将来发送 configure，仍是独立风险决策，
不能因为厂商库“忽略 -40”就自动放行。

`serializeClientParams` 用 QCBOR：先写入 map key `0x16`（22）为参数个数，再按
`keymaster_key_param_t`（步长 0x18，UINT 值在 +8）把每个 tag/value 编进同一容器。
本轮本机 Unicorn 无法复跑编码（ARM64 fetch 异常）；**未**产出可发送的逐字节
请求，仅固定了函数与立即数结构。

AOSP 常见整数打包（模型，非实机编码证明）：

| 字段 | 运行时属性 | 模型整数 |
|---|---|---|
| `KM_TAG_OS_VERSION` `0x300002c1` | release `17` | `170000` |
| `KM_TAG_OS_PATCHLEVEL` `0x300002c2` | `2026-10-05` | `202610` |
| `KM_TAG_VENDOR_PATCHLEVEL` `0x300002ce` | `2026-10-05` | `202610` |

OTA 静态属性曾为 system patch `2026-10-01`、vendor patch `2026-08-01`；与运行时
不同，**不能**拿 OTA 属性代替当前手机值。

## TA 静态事实

命令表（89 项，VA `0x5a5e0`）：

| 命令 | 表项 | 处理 VA |
|---|---|---|
| `0x2116` configure | 第 86 | `0xb7b4` → 核心 `0x37f28` |
| `0x215` date-support | 第 39 | `0xdcf8`（已实机成功） |
| `0x200` getVersion | 第 18 | 已有 |
| `0x311d` convert storage key | 第 42 | `0x29df0` |
| `0x3121` setVersion | **无** | 与照片 -40 一致 |

核心 `0x37f28`：

- 读取 CBOR map key `0x16` 得到参数个数
- 循环比较 tag：`0x300002c1` / `0x300002c2` / `0x300002ce`
- 命中后分别调用 TA RAM 写入桩：`0xb808`、`0xb864`、`0xb91c`
  （按 slot 索引写入 `0x5b4f0` / `0x5b4f8` / `0x5b4fc`）
- **三个 tag 必须都出现**，否则走
  `!!! The OS Version / Security or Vendor Patch Level not provided !!!`，
  返回 **-38**；未知 tag 返回 **-40**
- 成功路径在三者齐备后调用 `0xdd54` 等收尾

因此：即便将来授权发送 `0x2116`，缺任一 OS/补丁字段都会失败；写的是 TA 内
按 slot 的状态槽。是否进一步持久化到 RPMB/安全存储**仍未证明**。

字符串侧还出现 `deserializeConvertStorageKeyToEphemeral`、
`KM_TAG_FBE_ICE - using FBE ICE`，说明 decrypt 相关能力在同一 TA 内另有命令/标签，
不是 configure 单独能覆盖的。

## 对“解密 data”的含义

只读结论：

1. `date-support` 成功 ≠ 已 configure ≠ 可解密
2. 厂商正常路径会在 setVersion 之后发 `0x2116`，且 TA **强制**三字段
3. `0x2116` **不是**已证明的解密充要条件；其后至少还有 convert（`0x311d`）、
   metadata `keymaster_key_blob`、FBE/ICE 等独立环节
4. 当前策略保持：不自动发送 `0x2116`

可复现检查：`tools/audit_fuxi_m3_configure_static.py`（见候选
`out/m3-date-support-v1/configure-static-audit.json`）。

## 2026-10-30 更正与实机证据

本文前面的 `202610` 是当时按 AOSP 月级整数建立的**模型**，不是本机编码结果。
后续固定 QTI 编码器与离线执行确认：在已实机成功的 date-support 模式下，两个
补丁字段都使用 `YYYYMMDD`，因此实际值为：

| 字段 | tag | 值 |
|---|---|---|
| OS version | `0x300002c1` | `170000` |
| OS patch | `0x300002c2` | `20261005` |
| Vendor patch | `0x300002ce` | `20261005` |

六种字段顺序与厂商序列化逐字节一致；CBOR 为
`a416031a300002c11a000298101a300002c21a0135288d1a300002ce1a0135288d`，
外层命令字为 `0x2116`。

status-v2 实机照片取得了此前缺失的具体返回码：首条 recovery `begin` 返回
`FFFFFFC0`（-64，`KEYMINT_NOT_CONFIGURED`），commands1、retained1，未取得
operation handle、明文或 update/finish/abort 调用。照片与镜像 SHA 见
`out/m3-key-recovery-status-v2/attempt-01/`。

固定 TA 的离线执行进一步确认：

- `begin` 在进入密钥处理函数前检查 configured 标志；未配置时返回 -64。
- public configure 解析器要求三个 tag 全部出现；缺少任一字段返回 -38，未知 tag
  返回 -40。三字段齐备后设置标志，并写入 TA RAM 的 slot 状态槽
  （`0x5b4f0`/`0x5b4f8`/`0x5b4fc` 与一个字节）。
- 固定 `0xb7b4` wrapper 的成功形状为 SMC 返回全零、响应容量 `0x9fd8`、
  payload 长度 `0x9fd0`、输出区全零；该形状来自离线固定 wrapper，不是实机成功。

13 组解析/门测试、6 组厂商请求对照与运行时/参考库代码等价性记录在
`docs/evidence/fuxi-m3-configure-gate-20261030.json`，SHA256
`817bc13d0783d79380a054cfa0b6e5fa27d86a44b245a649016f1fbe1f6c2c32`。

`m3-key-recovery-configured-v3` 据此在同次启动、首条密钥请求前发送一次固定
configure，再执行现存密钥恢复。它只验证该 -64 门是否可解除；成功也不证明
configure 持久化、storage-key convert、HWKM/ICE 装槽或 userdata 明文。
M3/M4/M5 仍未通过。可复现审计：
`tools/audit_fuxi_m3_configure_gate.py`、`tools/audit_fuxi_m3_configure_static.py`。
