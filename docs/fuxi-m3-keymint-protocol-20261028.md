# M3 C2：KeyMint/QSEECom 本机请求映射 — 2026-10-28

仅静态反汇编用户提供的 A17 TWRP 文件，不执行厂商代码或 TA。此前 root register
与 loader open 的合成主机原型仍有效，尚未成为可上机的 invoke 执行器。

## 固定输入与新证据

`libqtikeymint.so` SHA256
`657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb`；
`libkeymasterdeviceutils.so` SHA256
`1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2`。
`tools/audit_fuxi_m3_keymint.py` 核对 SHA、字符串地址与特定函数中的指令和调用；
`tools/test_fuxi_m3_keymint_audit.py` 的正确输入与两个修改文件拒绝测试通过。
证据在 `out/m3-keymint-protocol-v1/{audit.json,tests.json,*.asm}`。

| 本机二进制位置 | 静态事实 | 对实现的含义 |
|---|---|---|
| deviceutils 0x62b0..0x62f0 | 从 `/vendor/firmware_mnt/image` 优先加载 `keymaster64`，失败回退 `keymaster`；QSEECom buffer 0xa000 | app-loader UID 122 是加载器对象，不能当 KeyMint TA UID；8 KiB C1 页不是完整 40 KiB QSEECom 用户态缓冲 |
| deviceutils 0x6334..0x6354 | 加载后先发送命令 0x200，读回版本字段 | 不能从 load 成功直接跳到 convert |
| qtikeymint 0x325dc..0x32600 | init 的命令号为 0x311d，然后 serializeConvertStorageKey | 得到 convert 命令号和独立序列化入口 |
| qtikeymint 0x39d90..0x39dd8 | QCBOR OpenMap，AddBytes 的整数 label=23，Finish | 推断 CBOR `{23: bstr(blob)}`；没有执行库，尚未取得逐字节等价证据 |
| deviceutils 0x6790..0x67a4 | 清零 0xa000，先写 32 位命令，序列化区从 +4 开始 | 请求外壳是 LE32 command 后接序列化字节 |
| deviceutils 0x67d0..0x6844 | send length=payload+4；response offset=align4(send length)，capacity=0xa000-offset；响应先读 status，再读长度，payload 在 +8 | TA 返回状态与 SCM 状态分开；仍需额外做长度/边界校验 |
| qtikeymint 0x326b4..0x326cc | sendCmd 成功后调用 deserializeClientExpKey | convert 输出不是可以直接按裸 AES key 使用的任意字节 |

## 更正此前的版本表述

`keymint_set_version()` 0x2e26c..0x2e37c **不是直接发送 Android release 17**。
它用命令 `0x3121`，通过 `serializeInteger` 发送固定 `0xc8`（200）。这可表述为
接口/协议版本协商线索，不能把整数 200 解释为 Android OS version。
`configure()` 的非 legacy 分支先调用它，再用 `0x2116` 和 `serializeClientParams`
发送配置参数。此前 A16/A17 的 release 属性变化仍是独立的版本绑定假设；
本轮没有证明具体配置参数、编码后 OS version/patch 或设备 TA 接受的值。
不据此改写已有未提交的交叉分析稿。

## 下一次最小 invoke 的设计边界

先用合成消息验证 root handle 1、registerWithCredentials op 5/counts 0x1100、
null input object；其后才是 client-env open(op 0/counts 0x1001) 的 UID 122 loader。
必须先核实本机 SCM descriptor 的 owner/arginfo、a0 与对象 result/response-type
的分层、同步中断恢复、输入/输出两页的物理与缓存契约、callback/piggyback 和远端对象
release。现有返回解析原型对未知状态只隔离资源，不能替代真实回调处理或授权。

C1 成功不会补齐这些条件，因此本轮 C1 不发 invoke，也不把 KeyMint 命令号直接
接到 SCM。C2 当前交付是可复现的固定输入审计与请求映射；没有 C2 上机镜像，
没有 root/client-env/TA 实机会话、密钥转换、ICE 装钥或解密结果。
