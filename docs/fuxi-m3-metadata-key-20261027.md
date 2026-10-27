# M3 metadata key 目录只读发现 — 2026-10-27

## 范围

新增默认关闭 `FUXI_M3_METADATA_KEY`，只在驻留诊断候选启用，并要求
`FUXI_UFS_M2_FILES=1` 与 `FUXI_UFS_DIAGNOSTIC_PARK=1`。它在既有 M2 文件读取之后，
用同一套只读 F2FS 读取器打开 metadata 分区上的固定路径：

```text
/vold
/vold/metadata_encryption
/vold/metadata_encryption/key      # 目录或普通文件都接受
```

`/key` 是目录时最多列出 6 个条目，对其中的普通文件（最多 3 个，单文件上限
8192 字节）逐块读取并计算 SHA256；不超过 16 字节的文件额外打印前 16 字节的
十六进制前缀（版本文件是公开的 `1`）。不打印完整内容、不落盘、不装钥、
不调用 SMC/TA、不解密。路径、条目数、文件数和大小上限都是编译期常量，任何
超限都只报告并停止，不做分块流式输出。

`tools/test_fuxi_m3_key_paths.py` 用独立合成的 F2FS 镜像（含
`/vold/metadata_encryption/key/{version,blob}`）编译生产读取器，验证嵌套目录
查找、目录列举、1 字节与 96 字节文件读取以及缺失路径拒绝；ASan/UBSan 通过。

## 候选与检查

`out/m3-metadata-key-v1`：镜像 `Mu-fuxi-m2-metadata.img` SHA256
`04467d7df7a820f885c0abd2c61288ab379d3bb525131a8891c8da3c8a975f67`。
13 项交付检查退出 0；交付与两种对照模块的 `smc #` 指令均为 0；交付 EFI 含
全部 `FUXIM3 KEY` 标记。主机测试覆盖 M2 既有路径、密钥路径读取和 SMC 构建器。

## 未验证边界

- 实机 `/metadata` 的实际布局、`key` 是目录还是文件、blob 大小与哈希均未取得。
- TWRP 曾以 rw 挂载 `/metadata`；若 checkpoint 不干净，`F2rPrepare` 会按策略拒绝，
  本候选不会绕过。
- 8 KiB 上限与 3 个文件的限制是诊断策略，不是布局结论；超限文件只报大小。
- blob 是 KeyMint/硬件保护的 storage key，不是可直接使用的 AES-XTS 裸密钥；
  即使拿到哈希也不证明可用性、权限或解密成功。

## 下一步

按实机读到的名称/大小/版本决定 KeyMint 请求与 `/metadata` blob 的对应关系，
再设计有界、可回收的 TA 交换；在此之前不加载 TA、不写 key 分区。
