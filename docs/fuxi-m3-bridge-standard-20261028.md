# M3 标准桥 ABI 纠正 — 2026-10-28

## 固定二进制证据

本地 A17 TWRP qcom-scm.ko SHA256：
8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5。
这属于固定本地模块事实，不等于部署固件所有细节相同。新增审计固定指令并拒绝篡改输入：

- enable @4358：type w4=0 @43dc，__scm_smc_call @43e4；SCM 成功时取 low32(res[0]) 服务结果 @4404..440c。
- create @4560：owner2/serviceC/cmd1E/arginfo4/type0 @45f0；res[1]（sp+10）作为64位句柄 @4620..4624；low32(res[0])（sp+8）作为服务结果 @4628..463c。
- delete @445c：type0 @44ec，res 指针为 null @44e8，只消费 SCM a0；不能凭空增加 a1 服务检查。
- __scm_smc_call 的 bit31=(type==1)，bit30=SMC64；四参直接 x2..x5，x6/x7零；参数数达到5才进入扩展缓冲分支。@8948..8954 的 res[0..2] 来自 a1..a3。

故标准桥入口是 42000c1c/42000c1e/42000c1d。create 采用保守接受子集：
a0=0、a1=0、a2非零64位句柄。enable 同时要求 a0=a1=0。拒绝零句柄或非零服务高位不等于证明固件错误。

## 对旧结论的更正

此前代码用了 fast C2000C1x，并把 a1 当成32位句柄，未匹配上述包装。
撤回旧 C1/C2 中将照片 a0=0/a1=5C/a2=0 解释为“标准桥已注册 handle5C”的判断。
历史原图和日志保留；文件读取/hash 观测仍有效。旧删除是否作用于正确注册也未证明。
本修正不解释准确的 FFFFFFFF80000001，不能据此宣称 C2 根因已经确定或修复。

## 本候选范围

改动层是 UEFI DXE 和工具。M2/UFS 停队列及 INFO gate 后分配低4GiB连续8KiB零页，
仅测一次标准桥 enable/create/delete，打印 a0..a3 和完整64位句柄。
无 root/对象、blob/key读取、TA、解密、接收器或分区写入。
create未知完成或delete失败时，不再擦写、删除或释放页；只有确认删除才free。
未调用create之前失败则释放私有页。无自动重试/恢复，SMC没有硬超时。

物理/权限字、VM count=0、VMID bits和可选0x1a状态仍为此前有界编码；
未复现Linux完整pool/DT/VM所有权/安全世界缓存契约。这也是需先桥闭环而不进入C2的原因。

## 验证

固定模块指令及篡改拒绝；标量测试拒绝旧返回形态和5个以上直接参数。
12个ASan/UBSan生产桥生命周期向量覆盖高64位句柄、enable服务错误、create原始/服务/零句柄错误、
delete错误和未知态不擦写/释放。既有C2双模式56向量、C1生产F2FS/SHA和INFO五向量回归通过。
15项完整交付检查退出0，56个交付源码绑定。硬件pending；C2仍未通过。

## attempt-01 实机结论

照片IMG_7170..JPG，SHA256 8563c25f02596aed3fc1ed2752d409c406b082dde2797bafd01bb6e8cd61ff8a。标准桥生命周期未通过：
ABI=standard64；页phys=C6A40000、bytes=2000。
enable x0=42000C1C/x1=0，返回a0=a1=a2=a3=0。
create x0=42000C1E，参数C6A40000/C6A40006/2000/0，返回a0=0/a1=5C/a2=0/a3=0。
按本候选采用的固定模块ABI，没有可接受的零服务结果及非零a2句柄，decode=Not Ready。
retained handle=0 bytes=2000；照片可见无delete，按生产失败路径未擦写/释放页，无自动重试。
与旧fast桥照片同样raw create返回，故改变call-type未解决创建接受问题。
不能把5C猜作具体权限/地址/VM错误，也不能排除部署固件ABI与模块参考不同。
UFS stop=1、db=tdb=run=0、hcs=10F、is=0、poisoned=0、ready=0，stage=m3-bridge-standard。
SMMU GFSR=0、FSR=400残留，完整恢复未证明；PARK和cached report end可见。
未调用root/对象、TA、密钥或解密。15项检查、镜像59ef12959f32ef2869f328eaf258abeeca5c6f2b1f2880c56303756f701d2ad8及提交33e50f3aefb23346e407a25302efab7c44dfe3cc的56个源码绑定仍有效。
本次把未验收点定位到对象调用之前的桥创建契约；准确5C含义及VM/DT/permission/pool要求仍待静态核对。
C2仍未通过，不继续猜句柄或进入对象调用。
