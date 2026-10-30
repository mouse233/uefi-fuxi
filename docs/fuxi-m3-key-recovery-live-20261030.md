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
