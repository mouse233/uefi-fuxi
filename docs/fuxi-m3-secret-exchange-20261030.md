# M3 本机无 seed 绑定证据与无日志 SMC 交换适配（2026-10-30）

接 [恢复后端 wire/SMCI 封装](fuxi-m3-recovery-backend-20261030.md)。本轮取得当前手机
Android vold 的**运行时无 seed 绑定证据**，并实现实际 ArmCallSmc/缓存交换适配。
适配尚未由固件恢复入口调用；没有新启动镜像、UEFI 上机或真实 KeyMint 恢复。
没有发送 configure、重启、flash、分区写命令或读取密钥内容。**M3 未通过。**

## 本机绑定上下文：从未知变为有直接证据

开工时 ADB/fastboot 均不可见；用户确认在 Android/TWRP 后重新检查，ADB 恢复，
实际为 fuxi Android17、serial fcde91e、slot `_a`。先按互斥规则确认无传输任务。
`vold.has_key_storage_binding_seed` 不是本机二进制使用的属性名；固定 vold 中找到的
属性为 `vold.storage_seed_bound`。两者读取均为空，**缺失属性没有被当作无 seed 证明**。

使用已有 su 只读复制 `/system/bin/vold`，本机与主机完整 SHA256 一致：
`9c20de9cb015e066474ad9cc23e1364d5ddf4fa55fca5f2c9a57e3ad0caed418`（1,045,808字节）。
从其 `.gnu_debugdata` 找到本机 KeyStorage 符号，再核对实际指令：

| 固定 Android vold 位置 | 事实 |
| --- | --- |
| initializer `0x4a150..0x4a178` | 分配72字节、清零vector/state，指针写到VA `0xf9790` |
| retrieveKey `0x46520` | 调用 application ID helper `0x46bf8` |
| helper `0x46cf4..0x46d30` | 经同一指针读state+24；state1追加seed；首次state0写state2 |
| setKeyStorageBindingSeed `0x479fc..` | state2拒绝设置；state0才写state1及seed vector |
| property setter `0x47bbc..0x47bf0` | 仅设置seed路径使用字符串 `vold.storage_seed_bound` |

`tools/audit_fuxi_vold_binding.py` 固定完整输入SHA、上述范围与布局，不执行设备代码。
`tools/collect_fuxi_recovery_binding.py --android-vold` 随后对真实进程执行有界只读采集：

- 验证产品、serial、release、已存在root、唯一vold进程、`/proc/<pid>/exe`完整SHA及
  唯一可执行映射原点；要求 `/data` 已经是dm路径上的F2FS。
- 从固定全局位置读8字节对象指针，仅跟随到私有可读写匿名分配中的28字节头
  （vector三个指针+4字节state），连续两次；核验PID启动时间与maps保持不变。
- Android堆指针只去除AArch64 top-byte tag，再检查低48位地址/对齐/映射。**不跟随
  vector begin/end/capacity，不读取seed、密钥、认证令牌或解密内容。**
- 仅当state=2且vector三指针全零才产生成功报告；state0/1/未知、变化或短读均拒绝。
  不把原始指针或内存字节写到报告。总进程元数据读取量为72字节。

本机采集时间 `2026-10-30T02:59:32Z`，vold PID833，`/data`=`/dev/block/dm-47`；
两次均为 **state2 / used without seed / empty vector**。四个固定metadata包装文件只做
stat大小核对：version=1、secdiscardable=16384、keymaster_key_blob=208、encrypted_key=276，
与当前恢复库子集一致，没有读取这些文件内容或其摘要。

可提交的非秘密证据在
[`evidence/fuxi-m3-android-binding-20261030.json`](evidence/fuxi-m3-android-binding-20261030.json)。
完整主机归档为 `out/m3-secret-exchange-v1/{android-binding.json,android-context.json,
android-vold-input.json,android-key-file-sizes.json,vold-binding-audit/}`。

这支持后续候选针对**本次固定Android上下文**显式选择空seed，替代此前的未知状态。
它不证明UEFI成功恢复、每个keyblob属性、GCM认证或configure是否必需；这些必须由
实际恢复结果验证。已有TWRP空状态静态推论仍不能冒充本机运行时记录。

## 实际交换与归属接口

新增 `M3SecretExchange.c/.h`，直接实现 `FKM_EXCHANGE` 回调：

- `FUXI_M3_SECRET_EXCHANGE` 在独立DSC与fuxi平台均默认0；关闭时所有接口返回
  unsupported，不调用SMC或缓存函数。显式 `--secret-exchange` 仅编译库，没有运行入口。
- `FseInitialize` 要求新的CPU上下文、同次启动已验证的活bridge/app/队列停机与归属
  断言、4GiB以下页对齐identity mapping，范围覆盖0x16000共享视图且不越界。
  `LeaseVerified` 仍须由真实会话调用者建立，不能因本轮拿到seed证据便自动置真。
- 固定对象invoke `x0=0x72000602,x1=0x224`；输入0x15000，紧随其后的输出页4096。
  只接受后端固定app/op0/counts424和310f/3111/3112/2113命令；不提供任意SMC接口。
- 提交前对完整共享视图WriteBackInvalidate；每个命令最多8次同一SMC的continuation，
  保留返回x6，重建固定输入寄存器及x7=0；不把interrupted call当成新请求重试。
  总命令预算19，足够begin+最多16次update+finish+一次失败abort。
- 只有四个raw返回寄存器全0才Invalidate并交给后端继续验证piggyback/描述符/TA/CBOR。
  未知返回、resume耗尽或输入不合格则隔离；不擦除、释放、删除bridge或发新调用。
  同步SMC本身仍没有软件硬超时，次数边界不等于墙钟超时保证。

`FsePermitCleanup` 只在后端无活operation、未隔离、私有请求与共享视图都已CPU清零时，
把擦除WriteBackInvalidate到物理内存并撤销继续交换权限。**这不是远端对象释放或
bridge删除证明**；app/loader/env release、bridge delete及其失败保留仍须由会话层完成。
后端/transport任一未知、handle仍活或任何残留字节都会拒绝清理许可。

库无logger/allocator/free/delete依赖；实际启用对象仅导入 `ArmCallSmc`、
`WriteBackInvalidateDataCacheRange`、`InvalidateDataCacheRange`。旧查询诊断的缓冲区
打印没有被接入该回调。当前固件入口没有调用本库，不能把函数实现说成实机已连通。

## 验证与剩余接线

独立包 `out/m3-secret-exchange-v1/REVIEW.md`：

- 24项绑定采集器合成用例通过，覆盖错误机型/版本/二进制、映射/身份变化、短读、
  state0/1/未知拒绝及Android tagged pointer；合成报告显式标记，不能作为设备证据。
- Linux容器内25项生产交换→后端→恢复核心 ASan/UBSan 用例与默认关闭检查通过。
  覆盖x6续接、8次上限、四层错误、坏piggyback、TA失败/abort失败隔离，以及活handle、
  未擦除请求/共享页、19命令预算耗尽时拒绝清理。monitor合成，未执行真实TA/GCM。
- 默认/query/显式exchange三个AARCH64模块模式构建通过；6个EFI绑定、4个恢复对象、
  三个交换对象的模式与导入白名单检查通过。默认对象无依赖，启用对象只含上述3项。
  未使用库仍会被链接器丢弃，EFI不变不构成新增路径硬件证据。

初次主机测试包含unused helper编译错误；低地址identity gate在macOS受PAGEZERO
限制，修改PAGEZERO的测试程序被SIGKILL，已撤掉该尝试，改用Linux容器完成实际低
地址分配及sanitizer验证，没有放宽生产地址检查。普通shell读取vold失败后使用既有
su只读复制并核对SHA；没有把失败输入带入运行时偏移采集。

下一项明确工作为**固件恢复入口和会话收尾**：绑定这份实机证据，在UFS读四文件后
完全停队列；同次启动建立app/bridge，再接FseExchange完成一次现存密钥恢复；未知
状态保持驻留，已知终态才擦除/收尾。随后才是convert、HWKM自有槽、ICE/DUN与一次
userdata metadata块明文对照。本轮没有新启动候选、重启或UEFI调用，历史SMMU
FSR400仍未解释，M3/M4/M5均未新增实机通过。
