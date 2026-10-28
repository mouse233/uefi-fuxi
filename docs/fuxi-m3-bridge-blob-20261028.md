# M3 C1：已注册桥页内的 metadata blob 读取 — 2026-10-28

改动在 UEFI DXE 诊断与构建/检查工具层。默认关闭 `FUXI_M3_BRIDGE_BLOB`，
要求原有 bridge call、INFO 自查询、M2 和诊断驻留开关；不改 DarwinBoot 或 XNU。

## 候选行为

先完成既有 INFO 与 M2 读取，再在 UFS 队列仍有效时分配低于 4 GiB 的 8 KiB
页区并执行 enable/create。create 成功后，生产只读 F2FS 读取器检查
`/vold/metadata_encryption/key/version` 为单字节 `1`，将普通文件
`keymaster_key_blob` 直接读进注册页。要求长度为 208 字节，SHA256 为
`9a57f01af0b8c9836cdf04f9abc2f83ad21baf94527b2c80b18b06f04ab2321e`
（昨天实机值）。写回/无效缓存后重新计算页内 SHA，通过后才打印前 32 字节。

读取失败也进入 delete 清理；delete 前清零并同步全部 8 KiB。只有 delete
返回 a0=0 才释放注册内存。create 非零/未知完成或 delete 失败时保留已擦净内存，
不重试 SMC，最终驻留。enable 失败或 create 之前的构建失败可释放尚未登记的页。
同步 SMC 没有硬超时，卡在 begin 行时需保留画面。此次同时修复旧 bridge probe
删除失败仍释放页的问题；旧候选镜像未覆盖或改写。

没有调用 TA、装入 ICE keyslot 或解密数据。页内哈希和 bridge 返回成功只证明
普通世界的读取与注册生命周期，不能证明安全世界/TA 能访问或已经消费 blob。

## 验证

`tools/test_fuxi_m3_bridge_blob.py` 编译生产 F2FS、SHA、C1 读取与桥生命周期代码，
用合成 208 字节数据及模拟 SMC/分配/缓存运行 ASan/UBSan：覆盖普通块和 inline、
版本错误、大小错误、路径缺失、错误哈希、缓存后数据变化、池/页分配错误、读取错误、
enable/create/delete 错误。create 未确定完成及 delete 失败均断言页未释放且已清零。
这些测试不执行真实 SMC，不使用实机 blob。

完整交付检查 14 项退出 0，包含 SMMU、route、receiver、USB state、M0、M1、
报告缓存、M2 draft/files、独立 f2fs-tools、桥标量构建器、C1、组合镜像及 UFS 交付。
交付 EFI 有 1 条 smc，no-smc 与 scm-query 两个对照模块均 0。
本地 `out/m3-bridge-blob-v1/REVIEW.md` 记录本次 SHA、绑定提交及独立 attempt。
