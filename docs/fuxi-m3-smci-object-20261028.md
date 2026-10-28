# M3 C2 object 命令对照候选 — 2026-10-28

## 上一轮实机失败与更正

`m3-smci-root-v1`（91775bf9…0a5dbe3）建立 8 KiB 桥后，legacy register
`72000600/224` 返回 `a0=FFFFFFFF80000001 a1=a2=a3=0`，OO 仍为 0，按策略
保留页/桥并停止，没有 release/delete/free。照片 e67f0676…0e6bdfe 已归档。
该 raw 错误未准确归类；不能按通用 -1、权限、内存错误或 TA 错误解释。
同时发现 cached report dropped=1，PARK 行不在照片中。

此前本机二进制核对确认了 legacy 描述符的存在和打包，却没有证明本机应选择
legacy，这是上一轮选择依据的缺口。INFO 同时报告命令 0/1/2 可用不能补齐该缺口。

## 入口选择依据与限制

固定参考驱动提交
[9e897228 的 smcinvoke.c](https://github.com/LineageOS/android_kernel_xiaomi_sm8550-modules/blob/9e8972287159837a256d0afcddc3f636f67ce8dd/qcom/opensource/securemsm-kernel/smcinvoke/smcinvoke.c)
仅当 DT 有 `qcom,support-legacy_smc` 时选命令 0，否则选命令 2。
新查到的公开
[43b5ada5 的 kalama.dtsi](https://github.com/LineageOS/android_kernel_xiaomi_sm8550-devicetrees/blob/43b5ada5654ed84c25f74789bc8f6326b7bacd20/qcom/kalama.dtsi)
中 `qcom_smcinvoke` 节点仅含 compatible，没有该属性。原文件归档到本次 Windows
reference/kalama.dtsi，URL/提交/SHA256 在 docs/evidence/fuxi-smci-entry-selection-20261028.json。

这是公开 SM8550 平台参考，尚未采集本手机运行时 DT/overlays，不能写成部署配置已确认。
因此本候选是有来源依据的 **命令 2 对照实验**，不是错误已归因或已修复。

## 改动与验收

- UEFI DXE 增加默认关闭 `FUXI_M3_SMCI_OBJECT`，构建参数
  `--m3-smci-root --m3-smci-mode object`。显式选择 object 命令 2，寄存器为
  `x0=72000602 x1=224`；其余 root register/null object、4 KiB 输入/输出、
  release、桥创建/删除及未知状态保留规则沿用 v1，无运行时 fallback。
- INFO gate 改为核对所选命令的 availability；仍不把 availability 当执行成功。
- 固定哈希 qcom-scm.ko @0x7270..0x733c 的 object descriptor 核验：svc6/cmd2、
  owner32、arginfo224、type2；保留 standard SMC64，不改成 fast call 或缩窄到 SMC32。
- 将 bounded report 容量从 96 增至 128 行，增加 12 KiB 静态缓存，保留溢出提示。
- 把实测 `FFFFFFFF80000001` 加入失败保留向量；legacy/object 各 28 项，合计 56 项
  ASan/UBSan 生产生命周期向量通过；C1 共享代码回归通过。
- 14 项完整交付检查通过，含报告边界/溢出/封存回放、两种对照模块与实际镜像绑定。
  实机需另看 root 对象句柄、release、bridge-delete/free 或 retained、报告是否完整。

改动只在 UEFI DXE 和工具层。没有读取 blob、加载 KeyMint TA、装钥或解密。
错误/回调/中断均保留资源驻留，未证实终态时不继续调用、不改写缓冲、不自动重试。
