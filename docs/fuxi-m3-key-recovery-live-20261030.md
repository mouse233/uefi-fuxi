# 现存 metadata 密钥恢复入口：m3-key-recovery-live-v1

2026-10-30，B线 `feat/twrp-data-uefi`，改动层为UEFI和构建/检查工具。
本候选的目标是同次UEFI启动中认证恢复现存metadata storage key，立即擦除结果，
并验证会话收尾。它还没有convert、HWKM、ICE装槽或userdata解密，不能算M3通过。
实机命令、镜像SHA256、检查和照片结论以 `out/m3-key-recovery-live-v1/REVIEW.md`
和规范 `usb-bulk.md` 最新条目为准。

## 输入与执行顺序

`M3RecoveryDiagnostic.inc` 在M2文件对照成功后，以既有只读F2FS接口读取固定四文件：
version、secdiscardable、keymaster_key_blob、encrypted_key。版本必须是ASCII 1，
大小必须为1/16384/208/276，application ID为personalized SHA512的64字节。
不记录文件内容、密钥摘要或前缀；旧key discovery/blob日志路径不参与候选。

空seed依据是已归档的本机Android vold两次稳定state2/空vector观察，而非属性缺失
或合成用例。构建器只接受完整SHA256为
`f2e5a8b406a8040e6834afcec72c31613adf1a840eec759ad7b10bacf74dedfc`
的证据文件，复制到候选并将摘要前32位编入诊断标签。身份、执行文件摘要与四文件
大小也检查。历史观察不能代替本次GCM认证；输入或绑定改变时应失败停止。

完成LUN4/keymaster双槽摘要核验和TA读取后，必须经过既有UFS停队列证明，
`!mReady && !mPoisoned` 才可进入安全调用。四文件/解析工作区为CPU私有内存；
UFS只使用原有独立bounce DMA窗口，未知UFS状态不进入KeyMint。

安全会话沿已验证的HLOS bridge→root→UID122 loader→load keymaster64→getVersion，
版本响应必须为4/1/4/1012。之后才启用无日志 `M3SecretExchange` 执行恢复库的
begin/update/finish，错误终态按既有契约abort。不会发送date-support、setVersion、
configure，亦无生成、升级或持久化分支。

恢复结果只有finish认证成功且operation关闭才可被当前调用者取得。这个诊断仅记录
长度和非秘密状态，随即 `FkrReset` 擦除结果及输入；`FsePermitCleanup` 验证共享页与
私有请求全零，并WriteBackInvalidate后撤销交换权限。然后释放app、loader、env，
删除bridge，清零并释放注册页。全部完成才有batch complete/retained=0证据。

未知SMC/续接、piggyback、描述符或CBOR归属，abort失败或关闭不明时保留私有work、
backend、exchange及注册页，不再调用、擦除、delete或free，最终驻留等待人工处理。
旧的公共查询日志仅在输入秘密前及共享区擦除发布后使用。固件默认仍关闭恢复入口
与真实交换开关，构建器要求显式完整选项和固定证据。

## 检查与证据界限

新增15项Linux ASan/UBSan入口用例直接编译生产恢复入口和SMCI生命周期，模拟文件
和monitor；覆盖成功擦除/全会话关闭、begin/update/finish已知失败、abort失败、未知
SMC、回调/输出畸形、版本不符、分配/文件失败、存储未停。未知路径快照验证共享页
未被修改，正常FreePool前检查私有分配全零。这些不是真实TA或GCM认证成功。

资格工具统一运行version、TA reader、resume及恢复后端/交换/绑定/入口检查，避免
交付检查依赖手工遗留报告。候选源码、交付FD内EFI、诊断字符串、SMC数量、证据
摘要和检查报告互相绑定；默认与query模块顺序重构建。后端另加非秘密Fault编号，
用于区分归属、SMC、piggyback、长度、不变输入、envelope、TA状态、abort及CBOR故障。

仅fastboot命令成功不证明恢复、擦除或会话关闭。应以照片同时核对RECOVERY结果、
fault、BATCH stop/passed、SMCI retained、最终UFS状态与诊断驻留。预期成功组合是
RECOVERY Success/bytes=248/retained=0、BATCH complete/passed=2ff、SMCI Success/
retained=0；这些是待验证条件，不能预填为实机结果。

下一阶段仍需保持恢复结果在明确归属下接convert/HWKM初始化、自有槽与清理、六参
SCM和UFS实际提交层DUN，再做一次已知userdata metadata块明文摘要对照。本候选
主动擦除恢复结果，后续不可跨重启复用。历史SMMU FSR400未解释，M4/M5均未通过。

## attempt-01 实测与 status-v2

`live-v1` 固定镜像SHA256
`eb181da061317d1d04eaa4cf6d2812bcd0bd0197c3bb751670bc68585748c2e0`，
26项资格检查/75源码绑定通过。fcde91e/fuxi/unlocked yes/slot_a核对后一次fastboot
boot退出0。照片已归档该候选attempt-01，显示M2文件/四文件prepare和LUN4两槽摘要
成功，UFS stop1/db0/run0/tdb0；getVersion 4/1/4/1012、续接1次。

首条恢复begin返回后：Not Ready/state5/stage1/km0/bytes0/retained1，
fault7/exchange1/commands1/resumes0；BATCH stop=key-recovery/passed=A3，env2/loader3
仍保留，SMCI Not Ready/retained1，最终PARK、poisoned0/ready0。FSR仍400。
未接受operation handle或明文，不执行update/finish/abort/清理/重试。km0是尚未
解析状态的默认值，不能解释为TA成功；M3未通过。

fault7只区分到“非零TaStatus且非负或Payload非零”，本照片没有具体status/length。
固定libkeymasterdeviceutils SHA `1c2172c4…3d7d2` 的sendCmd在0x6810读取status，
非零走0x6830原样返回；只有零status才在0x683c/0x6840取payload长度和指针。
所以不能从当前诊断断定错误响应畸形，更不能猜测缺configure；错误的payload长度
与operation归属仍需独立证据。离线反汇编和审计在status-v2目录。

`m3-key-recovery-status-v2` 仅补充经过原有响应边界/envelope检查后的公开头元数据：
header-seen、32位status、payload长度、wire响应长度；不读取/打印响应内容、密钥、
摘要或operation handle。ResponseHeaderSeen每命令清零，已验证头才置真。
旧fault7/隔离/调用预算/清理规则不变；不把未知响应改判成功或已关闭。
新增负status带payload、正status两组反例，入口17项、后端55项；两组都保持首条
命令后隔离，注册页快照不变，不再调用且没有明文。默认仍关闭，等待新的独立启动。
实际对象/链接map检查已纳入统一资格工具，避免只检查未使用库的EFI哈希。

status-v2 attempt-01已于2026-10-30 12:00 Asia/Shanghai临时启动，固定镜像
`c32884767117277ff89beb68b2fe2c4eedb6b7e675805ad0eafaf908320fc83e`，27资格/76源码
绑定及fcde91e/fuxi/unlocked/slot_a核对通过。fastboot发送/Booting exit0，总1.735s；
等待屏幕照片，尚无v2恢复/状态码或会话收尾结论，没有重试，M3仍未通过。

## status-v2 实测：首条 begin 返回 -64

status-v2 attempt-01 的照片/转录归档于
`out/m3-key-recovery-status-v2/attempt-01/`（HEIC SHA `20c70de8…2d1413`）。
四文件 prepare、LUN4、UFS 停机与 getVersion 成功；首条恢复 `begin` 的公开头为
`status=FFFFFFC0 payload-bytes=40616 wire-bytes=40624`，-64 即 AOSP
`KEYMINT_NOT_CONFIGURED`。恢复保持 Not Ready/state5/stage1/retained1，
commands1，未取得 operation handle 或明文，不执行 update/finish/abort，
BATCH 停在 `key-recovery`，最终 PARK。payload 40616 是响应容量减 8 的
wrapper 长度字段，不是解密输出。

该证据把“缺少初始化”从推测变成实机前提；仍不能仅凭 -64 证明 configure
成功后恢复必定成功。审计与下一步依据见
[configure 只读记录](fuxi-m3-configure-readonly-20261029.md)。

## configured-v3：一次固定 public configure 后恢复（主机通过，未上机）

`m3-key-recovery-configured-v3` 在 getVersion 之后、首条密钥请求之前发送一次
固定 `0x2116`，输入为 `170000/20261005/20261005` 与已验证 CBOR；证据 pin
`docs/evidence/fuxi-m3-configure-gate-20261030.json`
（SHA256 `817bc13d…6c2c32`）。configure 成功只接受固定 wrapper 的精确成功形状；
失败或完成不明时保留 bridge/object 与注册页并 PARK，不发送恢复请求。
成功后清零发布注册页，再进入既有恢复，恢复结果仍立即擦除。

镜像 SHA256
`5620674f194370b0ac480296c0df4986d28af1ba6c0d2fdee0894608e5f01888`
（1,888,256 字节）；28 项资格全部 exit0，81 个源码文件与提交/镜像绑定；
configured 入口 27 项、普通入口 17 项、后端 55 项、交换 25 项及默认/query
关闭检查通过。尚未启动 v3；实机成功只表示 -64 门被解除，不等于 TA 持久化、
convert、ICE 装槽或 userdata 明文。M3/M4/M5 仍未通过。详见
`out/m3-key-recovery-configured-v3/REVIEW.md`。

## configured-v3 attempt-01/02：configure 被接受，begin 返回 -62

两次照片（`attempt-01/screen-01.jpeg` SHA256 `aa69b26a…e89c27c`；
`attempt-02/screen-01.jpeg` SHA256 `b89a264c…0965faf0`）显示相同结果：

- `CONFIGURE begin once os=170000 os-patch=20261005 vendor-patch=20261005`
- `CONFIGURE return a0..a3=0 resumes=0`
- `CONFIGURE header status=00000000 payload=40512 wire=40520`
- `CONFIGURE Success；continue existing-key recovery`
- `RECOVERY result=Not Ready state=5 stage=1 km=0 bytes=0 retained=1`
- `RECOVERY fault=7 commands=1 resumes=1`
- `RECOVERY response-header=1 status=FFFFFFC2 payload-bytes=40616 wire-bytes=40624`
- `BATCH stop=key-recovery passed=4A3 retained=1`，最终 PARK

即：configure 的固定请求被 TA 接受，-64“未配置”门解除；但第一条密钥 `begin`
仍被拒绝，状态为 `0xFFFFFFC2`（-62），未取得 operation handle，恢复未开始。
`payload-bytes` 与 `wire-bytes` 仍等于容量与其减 8，属同一种“无输出错误”形状。
两次启动状态、长度与 `resumes=1` 完全一致，可复现。

> 更早的记录把该照片读成 `FFFFFFF2`（-14）；放大重读后确认是 `FFFFFFC2`（-62），
> `passed` 为 `4A3`。此前基于 -14 的 `km_check_key_id`／KM 分区归因作废。

### -62 的静态归属

整个 TA 只有两处立即数产生 -62，均在函数 `0x98c0`（`mov w19, #-0x3e`）：

- `0x9908`：`[obj+8]`（u64 版本）小于 `0xdde0()` 返回的 `0x4_0000_0005`
  时直接返回 -62，无日志。
- `0x9a1c`：先打印四个 `Key blob …Level` 值，再在键 blob 的
  osVersion/osPatchLevel（可能还有 vendor/boot patch）与 `0x5b4f0/0x5b4f4/0x5b4f8/
  0x5b4fc` 已配置槽不一致时返回 -62。

`0x98c0` 的调用者是键 blob 校验链（`0x347fc`、`0x3114` 处理函数）。begin 对这些
校验走的是操作结构里的函数指针（`0x8b1c` 的 `[x21+0x10]`、`0x8db4` 的
`[x19+0x40]`），所以直接 `bl` 边不可达，但 -62 只可能来自这里。

结论边界：本次 -62 命中的是“版本过低”还是“已配置字段与键 blob 不符”，从 HLOS
不可观测（TA 日志不对外）。同一设备上 TWRP 能正常解密，说明键 blob 本身可用，
嫌疑更偏向已配置槽内容或版本索引（`0x5a308`，可能与缺失的 `0x3121` setVersion
有关）。M3/M4/M5 仍未通过。
