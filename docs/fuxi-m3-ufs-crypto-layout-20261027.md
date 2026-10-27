# M3 UFS 加密读请求：仅主机布局草案

`tools/m3_ufs_crypto_layout.py` 只产生 16 字节合成头，不接入 UEFI，
不接受密钥、物理地址，不执行 I/O。它以现有 `FnuFillUtrd` 的读取方向
`0x14000000` 和初始 OCS `0xf` 为基底，按 Android 通用 UFS crypto 源码
的候选格式设置 crypto-enable `0x00800000`、低字节 slot、DUN 低/高字
到 words 1/3。调用者须提供合成 slot_count；其值不能视为设备能力实测。
输入边界严格检查，测试涵盖端序、最大值、槽位与类型错误，常规及 -O 运行。

参考 Android 通用实现：[ufshcd-crypto.h](https://android.googlesource.com/kernel/common/+/refs/tags/android14-6.1-2025-01_r9/drivers/ufs/core/ufshcd-crypto.h)、
[ufshci.h](https://android.googlesource.com/kernel/common/+/0d70da26afb1875ad5374b89a3ed19b7e036f4cb/drivers/scsi/ufs/ufshci.h)。
这不是 fuxi ABI 证明：必须核对控制器 crypto capability、keyslot 数量与
所有权、加密模式、数据单元大小、真实 DUN 映射、Qualcomm ICE/HWKM 和
是否使用厂商特有 PRDT 格式。不能仅凭该头提交实际命令或声称解密成功。
实现还需处理实际读请求的长度、分区起点、密钥编程和清除、OCS 错误及
失败后停止清理。目标文件的 fscrypt DE/CE 解锁仍属于另一层。
