# M3 UFS 加密能力只读探针（2026-10-27）

目标：在 UEFI 接管前读取本机 UFS 标准 CCAP 和最多四项 CRYPTOCAP，
为后续 ICE 算法和数据单元设计提供硬件证据。仅 CAP bit 28 与 HCE bit 0
为 1 时读取 CCAP；CCAP 全 1 则拒绝，配置数组基址与能力条目可能重叠或
超出窗口时停止。不读取 crypto configuration 数组，不写加密寄存器，不
使用安全调用、密钥、keyslot 或加密 UFS 命令。不会解密数据。

依据：[Linux UFSHCI 定义](https://github.com/torvalds/linux/blob/master/include/ufs/ufshci.h)
与 [Linux UFS crypto 能力初始化](https://kernel.googlesource.com/pub/scm/linux/kernel/git/jack/linux-fs/+/4b84a4c8d40dfbfe1becec13a6e373e871e103e9/drivers/ufs/core/ufshcd-crypto.c)。
标准位字段为候选解释，可能受 fuxi 厂商实现影响，成功读取不意味着 keyslot
空闲、能够安装密钥或支持 UEFI QTEE。HCE 加密使能状态也不能从 CAP 推断。

测试使用现有 UFS 控制器模型验证无能力/HCE 时零寄存器读取，限制最多四项，
拒绝配置数组重叠和全 1；运行 ASan/UBSan。候选保持 M1/M2 只读、M2 clean
checkpoint 检查、USB 前 PARK；不传 payload，不 handoff。寄存器范围虽受限，
实际 SoC 映射和可访问性仍需上机验证；如果屏幕停在 crypto-capabilities
阶段，保留照片并手动重启，不能声称探针成功。
