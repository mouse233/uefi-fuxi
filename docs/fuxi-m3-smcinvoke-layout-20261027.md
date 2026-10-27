# M3 smcinvoke 对象请求布局主机原型 — 2026-10-27

## 范围

仅依据固定提交的公开 SM8550 候选源码构造两种合成消息：root 对象使用
`registerWithCredentials` 传入 null object，以及使用假设的远端 client-env
handle 打开 UID 122 的 QSEE 兼容 app loader。构造器只处理合成内存字节，
不接受密钥，不执行 SMC，不访问设备，未接入 UEFI 或任何 I/O。输出对象、
回调、响应解析、对象释放、共享内存、KeyMint 协议和错误恢复均未实现。

候选源码指出 12 字节头、每项 8 字节、缓冲区 8 字节对齐，4096 字节最小
共享缓冲；register 方法 5/counts 0x1100，open 方法 0/counts 0x1001、UID
122。设备 TWRP `smcinvoke_dlkm.ko` 已在固定哈希下反汇编对照：`get_root_fd`
使用 root handle 1；`get_client_env_object` 的方法/计数为 5/0x1100；
`__qseecom_start_app` @0x1e44 使用 UID 122，@0x1e84..1e88 使用方法 0 和
counts 0x1001；`marshal_in_invoke_req` @0xbc10..0xbc38 显示 counts 四个
nibble、每项 8 字节、基础头 12 字节。局部事实吻合不证明完整协议、调用者
授权、缓冲映射或设备 ABI 等价；输出对象 handle=2 只用作合成测试示例。

`tools/m3_smcinvoke_layout.py` 包含两个受限构造函数，不提供通用对象执行器。
它拒绝 null、root、本地对象位、溢出和非整数 client-env handle。
`tools/test_m3_smcinvoke_layout.py` 的 4 项静态矢量、无效句柄与边界测试在
常规和优化模式下通过；增强后的 `tools/audit_fuxi_m3_qsee.py` 核验已绑定
的厂商二进制对象方法和计数，原始及篡改拒绝测试通过。

## M3 路径与未验证点

1. 确认 smcinvoke 的请求/响应封装、缓冲区大小、物理地址可访问性、缓存同步、
   owner、回调/中断与对象引用释放，设计失败时安全停止。现有原型不能替代这些。
2. 在不操作实际密钥前，证明 UEFI QTEE 会话建立与资源释放符合该设备 ABI；
   任何 secure-world 不接受的权限/状态都如实停止，不绕过验证。
3. 解析并验证 `/metadata` KeyMint blob 的目录和版本，结合本机 KeyMint 请求
   协议与版本绑定，安全获得受保护的 ephemeral storage key；不能输出或保存 key。
4. 按本机 HWKM 初始化与 SCM ABI 配置受控的 ICE keyslot，验证错误清理；
   availability 不是装钥成功。处理桥接内存权限、生命周期、slot 所有权与恢复。
5. 为原生 UFS read 增加经验证的加密上下文与 DUN，读取有界 metadata 块；
   与同状态 TWRP 明文 SHA/F2FS 数据对照并验证安全停机，才能认为 metadata
   加密层 M3 实际贯通。TWRP rw 挂载可能改变块，不能直接比较不同状态的哈希。
6. 目标文件若受 fscrypt DE/CE 保护，还需相应文件名/内容加密、key 策略及 CE
   凭据解锁；这属于完整文件读取的后续工作，不能由 metadata 块成功推断完成。

本轮无需手机操作，无 boot 镜像；不宣称 M3 已解密或估算可验证的完成时间。
