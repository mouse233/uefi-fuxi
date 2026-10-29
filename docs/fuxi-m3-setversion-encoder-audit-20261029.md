# setVersion 的厂商编码与版本分支离线复核（2026-10-29）

## 实机现象及边界

本机 a4fa6e2e…5594c31 attempt-01：SMCI 调用 a0..a3=0；setVersion 响应字段
status=FFFFFFD8（按 int32 为 -40），探针保留对象和桥并停止。Android 公开 Keymaster
[错误定义](https://android.googlesource.com/platform/hardware/libhardware/+/6507f50/include/hardware/keymaster_defs.h)
将 -40 命名为 `KM_ERROR_INVALID_TAG`。这是交叉线索；本设备专有 TA 的错误表和处理路径
尚未核实，不能证明 TA 的实际含义、具体哪个标签有问题或产生层。

## 厂商编码的执行证据

从 SHA256 68f3829b…f87da5 的 A16 TWRP 镜像恢复的 `libqtikeymint.so`、
`libqcbor.so`、`libkeymasterdeviceutils.so` 分别固定为 `657093d0…ddcb`、
`bda86553…2500`、`1c2172c4…d7d2`。前两项在 A16/A17 的一致性须按已有 A17 对照
证据理解；libqtikeymint 为此前固定审计输入，libqcbor 为从 A16 恢复的固定本地输入，
本次未独立取得 A17 libqcbor 原件比对。独立脚本
`tools/audit_fuxi_m3_setversion_encoder.py` 以 Unicorn 限界映射 ELF，跳转到各自真实
厂商函数；仅提供受限 libc 内存桩，不调用手机或安全世界。实际执行固定库的
`serializeInteger(200)` 及其 QCBOR 编码路径返回 4 字节 `a1 0b 18 c8`，与 UEFI 的
`SmciPut32(Page+0x64,0xc8180ba1)` 在小端机器上的字节相同。库 SHA 检查拒绝篡改，
返回状态/长度、到达的编码路径和执行步数都有检查。

该结果只证明序列化子集的字节一致，不证明 SMCI 消息与设备端厂商调用完全等价，
也不证明 TA 收到的缓冲区或版本上下文。厂商 `sendCmd` 从响应第一个 32 位字段读取
非零状态并返回，支持当前将其视为响应状态的分层，但不能由此归因。

## 版本路径

固定 deviceutils 的 getVersion 处理将响应的前四个字段依次存到状态结构偏移
+4、+8、+c、+10；这与照片中四个原始字段 4/1/4/3F4 的对应是基于调用/布局的推论。
在隔离模拟中直接执行厂商 `isLegacy`，(4,1) 返回 false；对照 (4,0)、(3,0)、(5,0)
分别返回 true、true、false。因此若照片字段对应上述结构，厂商会选择非 legacy
配置路径，该路径调用 setVersion；这并不能证明当前启动中的其他上下文相同。
厂商 configure 中调用 setVersion 后继续执行，并不证明可安全忽略这里的错误；
当前实验保留所有失败保护，不跳过错误、不发配置/密钥命令。

检查报告为本机候选 `out/m3-setversion-macos-20261029/encoder-audit.json`；此步骤没有
改变 UEFI 镜像或操作设备。下一步应固定参考并逐项验证用户态 QSEECom → 内核 → SMCI
请求/输出缓冲区、应用状态和响应写入差异；不要基于 -40 猜测替换标签或重试。

独立的固定参考模型 `build_send_request` 以 `21 31 00 00 a1 0b 18 c8`、
response capacity 0x9ff8、is64=true 得到 counts=0x424、页对齐长度 0x15000，
BI/BO 描述符依次为 `(0x60,8) (0x68,0x9ff8) (0xa060,0) (0xa060,4)
(0xa068,8) (0xa070,0x9ff8)`，与交付 UEFI 源码一致。这是独立构造模型与源码
的对照，不是设备接收字节的观测，也不验证该公开参考与设备固件完全一致。
