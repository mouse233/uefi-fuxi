# fuxi：将 TWRP 的 Android /data 读取能力移植到 UEFI

日期：2026-10-25。工作分支 `feat/twrp-data-uefi`，起点 `4fda548d`（实验固件的 `feat/ramdisk-test`）。独立检出为工作区内 `ramdisk-test/uefi-twrp-data/`；原实验检出的分支和未完成修改不随本工作切换。

## 1. 目标与当前交付

最终目标是：UEFI 在只读条件下，从 Android `/data` 的两个普通文件读取当前 iPadOS OS/SystemOS 镜像的**明文**，加载到拥有明确归属的 RAM，验证完整 SHA256，发布现有 RAM 对象交接，再由菜单进入 DarwinBoot/XNU。这样省去每轮通过 USB 传输约9.38GB对象。

本次实现的是 **M0 移植基础和诊断入口**，不是完整解密器：

| 能力 | 本分支状态 | 验证范围 |
| --- | --- | --- |
| 绑定用户提供的 TWRP 镜像、组件哈希和接口符号 | 已实现审计工具 | 主机重新解包、ELF 检查通过 |
| GPT CRC、分区几何/重叠/重复身份检查 | 已实现 | 512/4096字节LBA、损坏输入测试 |
| 只读、分区内限界读取 | 已实现 | 主机回调测试；UEFI BlockIo 适配已编译 |
| F2FS 两份超级块头部识别 | 已实现诊断 | 仅魔数和部分几何；不是完整超级块/文件系统校验 |
| SCM/QSEE UEFI 协议发现 | 已实现 | ARM64 编译；无实机结论 |
| SCM 调用存在性查询 | 已实现、单独开关，默认关闭 | 请求白名单/结果分类测试；ARM64 编译 |
| M1 原生 UEFI UFS 只读接管 | 已实现诊断（`FuxiNativeUfsDxe`，开关默认关闭） | 建模控制器主机测试、ARM64 编译；无实机结论 |
| 当前默认固件中的原生 UFS 提供者 | 默认固件仍无；M1 诊断镜像需显式开 `FUXI_DATA_PORT_UFS=1` | 不能因现有 BlockIo 缺失就尝试 DMA |
| F2FS checkpoint、NAT、目录和文件读取 | **未实现** | 不向后跟随头部地址 |
| 元数据解密、密钥解封、ICE装钥、fscrypt | **未实现** | 不加载安全应用或传递密钥 |
| 本地文件 → RAM 对象发布 | **未实现** | 当前 USB 发布链路没有改动 |

两种独立 DXE 模块变体均已在指定 ARM64 Linux 容器编译成功，82个主机fixture经 ASan/UBSan 通过。未生成新的完整启动镜像，未启动手机；没有资格宣称 UEFI 已能读取 UFS、解密 `/data` 或引导本地系统。

交付EFI反汇编另外确认：no-smc变体有0条SMC指令，query变体有1条。该检查证明编译开关落实到了二进制，不代表指令在手机上执行成功。

## 2. 参考输入和证据等级

输入：`twrp-3.7.1_12-v9.0_A16-fuxi-skkk.img`，104,857,600字节。

```text
image SHA256 = 68f3829ba4b7faaf8b873fd0dce7dabd03b2bdd750debbae56b1dbe326f87da5
cpio  SHA256 = 6973560a73525ae1bbf2c13102934067d45cac2344e93ca077b9d0097923ba93
```

用户已说明此 TWRP 能解密本机 `/data`。本轮没有重测该能力。镜像内 `ro.twrp.version.skkk.code=900`；文件名为A16，主程序版本字符串仍含A15，部分属性值混合了旧SDK和占位补丁日期，不能将这些字符串当作运行时版本证据。

镜像是 ramdisk-only Android boot v4，声明 header_size=1580，kernel_size=0；包含318个Linux模块，相关模块的vermagic为5.15.78。没有内核正文，不能从此镜像独立重建完整Linux配置。`ufs_qcom.ko` 保留符号和路径字符串，但没有 `.debug_info/.debug_line`，不能视为完整调试版本。

可复现的组件证据见 [接口档案](evidence/fuxi-twrp-v9-interfaces.json)。完整主机取证另见工作区 `boot-tests/2026-10-25-twrp-skkk-data-readonly-analysis/REPORT.md`；前一份误传的PixelOS Recovery不作为解密实现参考。

还有一条已有实机证据：工作区 `boot-tests/2026-10-23-ufs-readonly/observation.json` 记录 fuxi 在 **XNU** 中成功接管UFS队列、验证主GPT CRC并读取userdata首块。照片哈希和镜像哈希在该档案中。这是本机原始存储读取参考，不是UEFI存储或Android解密成功。此前只依据NativeUfs README中的sheng描述而遗漏这条fuxi记录，现予更正。

## 3. 从 TWRP 提取出的实际依赖

`system/etc/recovery.fstab` 和 `system/etc/twrp.flags` 一致声明：

```text
/metadata : f2fs
/data     : f2fs, inlinecrypt
fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0
metadata_encryption=aes-256-xts:wrappedkey_v0
keydirectory=/metadata/vold/metadata_encryption
UFS sysfs=/sys/devices/platform/soc/1d84000.ufshc
```

这描述镜像的目标配置，未核验当前手机的实时挂载状态。

`system/bin/recovery` 中存在已定义的 `Decrypt_DE`、`Decrypt_User`、`android::vold::retrieveKey/installKey` 及合成口令处理函数。相关vold实现已编进recovery；没有独立vold进程不代表缺少解密功能。

启动脚本明确安排：模块加载完成 → 启动qseecomd → listeners注册完成 → 启动Gatekeeper和KeyMint。keystore2使用临时工作目录。厂商库涉及 `/dev/qseecom`、`/dev/smcinvoke`、ioctl和Android Binder/HIDL/AIDL接口。

内核模块的静态符号链为：

```text
ufs_qcom → ufshcd-crypto-qti → crypto-qti-common → crypto-qti-hwkm → qcom-scm
                   keyslot program/evict         ICE set/clear、derive secret
```

这是静态依赖，不是已捕获的运行调用轨迹。KeyMint处理密钥材料与UFS在请求中使用ICE密钥槽是不同环节；仅复现其中一项不构成文件明文读取。

## 4. UEFI 中的目标分层

建议按依赖保持模块边界，逐项验证后连接：

1. **原始存储层**：本机UFS控制器、PHY/时钟、电源、SMMU、缓存维护、队列归属；向上只提供有界读取，不提供任意SCSI命令或写入API。
2. **只读文件系统层**：GPT定位 → 未受Android元数据加密的`/metadata`文件系统 → 读取密钥包装材料。F2FS文件读取需要checkpoint选择、CRC、NAT及journal、node/inode、目录和文件块映射。
3. **安全通信层**：复现本机需要的SCM/SMCInvoke/QSEE交互、共享内存和回调约定；保留安全固件的错误，不伪造KeyMint/Gatekeeper成功。
4. **元数据加密层**：对userdata实现与Android `dm-default-key`兼容的读取语义，核验密钥类型、数据单元编号、算法和ICE槽参数，不能用裸分区LBA套用所有层的DUN。
5. **fscrypt层**：读取文件policy、nonce、主密钥标识，按实际v2/inlinecrypt_optimized/wrappedkey_v0处理文件内容和目录名；按路径所在的CE/DE域处理认证依赖。
6. **RAM对象层**：将校验后的两个明文文件放入受保护窗口，发布现有协议。无需因此给XNU增加Android文件系统驱动。

只在`/data`中选择一个镜像路径，不能自动免除其父目录和文件的加密域。设备已解锁、文件已导出物理extent、TWRP曾经成功解密，都不能代替本轮UEFI的密钥初始化。普通重启不能作为解密状态或RAM内容继承机制。

### 4.1 代码复用方式

不尝试在UEFI直接执行Linux `.ko` 或Android `.so`。先从已知符号及源码确定必要接口，缩小需实现的路径。通用TWRP源码有助于上层vold/fscrypt流程，匹配的小米/高通Linux5.15模块源码更有助于SCM、ICE和UFS；厂商库仍可能需要接口分析。

本轮新增解析器和查询构造代码是独立实现，没有把Linux/TWRP源码或厂商二进制复制进固件仓库。后续实际复用代码时保留来源和原许可，不把不同许可的整块内核实现无说明地并入现有驱动。

## 5. 已实现入口的行为

文件位于 `Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/`：

- `DataReadOnly.c/.h`：无分配、无MMIO、无SMC指令的生产核心；只接收Read回调。
- `FuxiDataProbeDxe.c`：ReadyToBoot时执行一次的UEFI适配和诊断输出。
- `.inf`：独立DXE模块。

只接受设备路径明确含`UFS(PUN=0,LUN=0)`、非逻辑分区、非可移动介质的唯一BlockIo实例。没有或多于一个匹配时停止读取；不会扫描所有磁盘、复用RAM payload或猜测厂商设备路径。

介质ID、块大小和末LBA在读取前重新核对；分配按IoAlign对齐。GPT检查header/entry-array CRC、主/备头位置、可用范围、全部非空分区的范围及重叠、重复GUID和目标分区重名。128项/64KiB以上的表返回unsupported，不截断后继续。

只读metadata/userdata的前两个4KiB块以识别两份F2FS超级块头。F2FS返回success仅表示魔数和一组有界几何成立；没有验证超级块CRC、checkpoint或inode，不能据此跟随地址或宣称挂载成功。userdata不匹配F2FS可能仍是元数据加密，不能据此宣称文件系统损坏。

**重要限制：默认fuxi固件没有启用vendor UFS栈。** 这是M0的明确边界，不应为让探针通过而直接启用整个vendor栈。M1原生驱动（下节）以同一Read回调形态直接驱动M0的限界读取层。

## 5a. M1 原生 UFS 只读诊断（FuxiNativeUfsDxe）

文件位于 `Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/`：

- `UfsCore.c/.h`：无 MMIO、无分配、无缓存操作的自由独立核心。UTRD/UPIU 构造、单槽轮询、响应/sense 校验、停队列前置检查、SMMU 计划与配置回读全部为回调形式；数据方向只允许 0（无数据）与 2（设备到主机），写入方向在参数检查即被拒绝。
- `UfsSha256.c/.h`：独立 SHA-256（FIPS 180-4），用于原始块哈希；不链接加密库。
- `FuxiNativeUfsDxe.c`：DXE 调度时执行一次的 UEFI 集成（APRIORI 中排在 USB 接收器之前，因为 receiver-only 候选在入口内等待 180 秒后驻留、永远到不了 ReadyToBoot；此时 ConOut 已就绪）：GCC/HC 只读报告 → 空闲门（HCE、HCS 低半字节、双 doorbell、致命中断位，任一不满足不写任何寄存器）→ 独立 DMA 窗口（4 GiB 以下分配 139,264 字节，绝不覆盖 ABL 遗留请求列表）→ 停队列 → stream 0x60 SMMU 绕过配置（计划器从次顶 bank 开始，把最顶 bank 原样留给 USB 路由试验；拒绝与其他活动 stream 共享 bank）→ 起队列 → NOP → 电源查询（必要时 SSU ACTIVE 到 0xD0）→ TEST UNIT READY → READ CAPACITY（4096 字节块校验）→ M0 的 GPT/F2FS 限界读取 → 原始块 SHA256 → 再次停队列并打印 doorbell/故障寄存器。任何完成疑点（超时/致命状态）即隔离缓冲，此后不再发命令、不再触碰寄存器。
- 寄存器事实转录自已在本机 XNU 验证的 NativeUfs 驱动（2026-10-17/23 实机记录）：请求列表 0x50/0x54、传输 doorbell 0x58、run/stop 回读 0x60、任务 doorbell 0x78、致命状态 0x71880、UFS HC 0x1d84000/0x3000、GCC 0x100000、apps_smmu 0x15000000、UFS stream 0x60。这些是本机事实，不推广到其他 SM8550 设备。
- `MemoryMapLib` 新增 GCC 与 UFS HC 两个 MMIO 窗口（AddDev/NS_DEVICE，与 vendor uefiplatLA.cfg 同源风格）；映射本身不触碰硬件。
- 模块默认不进入固件：`FUXI_DATA_PORT_UFS=1` 时才编译进 FD。诊断只读、无 BlockIo 发布、无密钥操作；成功后控制器停机，失败后按 XNU 同款隔离规则处理。

## 6. SCM 查询的精确含义

两个固件开关默认均为0：

```text
FUXI_DATA_PORT_PROBE=1   # 将DXE模块纳入实验固件
FUXI_DATA_SCM_QUERY=1    # 另行允许直接SMC调用存在性查询
FUXI_DATA_PORT_UFS=1     # M1 原生UFS只读诊断进入固件（FuxiNativeUfsDxe）
```

仅开第一个开关时，只发现SCM/QSEE协议和读取已有UFS提供者；不调用安全服务。开第三个开关时，M1诊断会在DXE调度时接管空闲的UFS控制器并读取GPT/分区首块；两者都开时，新增调用只允许INFO/IS_CALL_AVAIL：

| 字段 | 内容 |
| --- | --- |
| x0 | `0xc2000601`（fast SMC64），或`0x82000601`（fast SMC32） |
| x1 | `1`，一个标量参数 |
| x2 | self=`0x02000601`，或ICE set/clear/derive主体`0x02001005/06/07` |
| 其余参数 | 0，无密钥或共享内存 |

ES服务号0x10及5/6/7命令号已与用户镜像的qcom-scm模块反汇编对照；query封装按公开Linux SCM ABI实现。**被查询主体不是实际执行的函数号**，本入口不执行set/clear/derive，不改变密钥槽，不装载TA、不调用RPMB、不进行分区写入。

先查自身。64位查询明确成功但返回不存在时才试32位；错误、busy、interrupted或非布尔结果均保持indeterminate，不据此宣称不支持。当前不实现continuation或盲目重试，出错后不发后续query。单次SMC可能受安全固件影响而不返回，主机侧限次不能作为硬超时保证；实机需用独立临时启动候选。

availability=true只证明固件声称支持入口，不能证明UEFI有权限取得Android密钥、正确安装ICE槽或读取文件。

## 7. 后续里程碑与停止条件

| 阶段 | 必须产出的证据 | 失败时停在哪里 |
| --- | --- | --- |
| M0 当前基础 | 输入绑定、主机损坏输入测试、两个ARM64模块构建 | 不作硬件成功推断 |
| M1 UEFI原生UFS | 空闲控制器检查、独立DMA窗口、SID路由readback/回滚、GPT及已知原始块哈希 | 未知DMA归属、活跃doorbell、异常OCS/UPIU或超时即隔离缓冲并停止 |
| M2 `/metadata`只读文件 | 已验证的双超级块/checkpoint和所需文件明文，与TWRP导出结果哈希一致 | 需要日志回放/修复、未知feature或NAT/journal不一致时拒绝 |
| M3 安全与元数据解密 | ABI/固件匹配、错误归因、受限装钥、userdata已知元数据块明文对照 | 不记录原始口令/密钥；认证、DUN、槽配置未验证不继续 |
| M4 `/data`已知小文件 | 正确域与policy，完整明文SHA256和TWRP/主机对照一致 | 仅能列目录、读到乱码或返回成功但哈希不一致都不算通过 |
| M5 完整对象加载 | OS/SystemOS全量SHA256、RAM归属、存储完全停机、协议绑定与DarwinBoot/XNU照片 | 不以USB消失或配置位当作停机/进入XNU证据 |

### 7.1 M1 的实施状态与剩余证据

实施已完成并按 NativeUfs **读取路径**转录：`RootQueue.h` 停/起队列序列、`RootCommands.h` 单槽提交与轮询、`SmmuTakeover.h` 计划器、`TransferPoll.h` 完成策略，全部对照源码逐行核对；持久化写入窗口未移植。GCC/UFS/MMIO、SID 0x60 等参数按本机 FDT 与 2026-10-17/23 实机记录重新核对；未推广到其他 SM8550 设备。

UEFI 与 XNU 的差异已处理：本机 DMA 窗口由 UEFI 分配器给出（4 GiB 以下，永不覆盖 ABL 遗留请求列表）；GCC/UFS MMIO 窗口经 MemoryMapLib 显式映射；缓存维护用 CacheMaintenanceLib（提交前 WriteBackInvalidate、完成后 Invalidate），行纪律与原驱动一致。

剩余为实机证据：空闲控制器检查、独立 DMA 窗口、SID 路由 readback/回滚、GPT 与已知原始块哈希都需要照片级上机记录；实机 userdata 首块 magic 应与 XNU 2026-10-23 记录的 `f673c25f 7086bec0` 对照。单次 SMC/命令可能受安全固件影响而不返回；超时即隔离缓冲并停止，不得转入 DarwinBoot。UFS 的 SID 和 context bank 不套用 USB 的 0x40 路由。退回菜单并不代替控制器停机。

实机阶段记录（2026-10-25）：阶段标记把首次崩溃定位到第一条带数据阶段的命令（`capacity`），根因是 PRDT 表项被误写成大端——UFS PRDT 是小端原生存储，只有 UPIU 字段是大端；字节翻转的 DMA 地址触发 SMMU 故障并整机复位。改为与 XNU 一致的小端存储后，两次实机启动诊断全程跑完、接收器完成枚举（主机侧 1209:0001 可见），UFS 诊断与 USB 路由试用在同一 SMMU 上共存（USB 按既有策略落到 ABL 留下的 context bank 5，顶 bank 未被动过）。诊断数值行走双通道（ConOut + 调试串口）；候选以 `FUXI_USB_EP0_TRACE=0` 静默接收器逐包 EP0 调试行，使数值块稳定保留在屏幕上供拍照。GPT/magic/SHA256/停机 readback 的照片采集仍在进行。

## 8. 接入现有 RAM 对象链路

以后由新的本地加载器调用公共分配/发布层，避免依赖USB协议的BEGIN/DATA/END状态机。当前`FuxiUsbRamDxe.c`仍是发布的实际实现，本分支尚未抽取或替换它。

目标对象来自实验内核仓库的 `package/UniXNUPkg/Include/Protocol/UniXNURamObjects.h`：OS长度6,077,580,800，SystemOS长度3,303,014,400，协议还绑定物理地址、大小和SHA256。读取的应是该协议对应的两个精确字节对象；不能把IPSW压缩包、任意解压后的APFS文件或仅APFS slice当成同一对象。

内存窗口skew必须从本次交付kernel.macho最低非空段重新推导；该头中某一版的0x7c000不是通用常量。完成读取后检查完整RAM回读哈希、UFS停止和DMA归属；DarwinBoot之后的XNU仍使用现有RAM块设备。跨重启缓存、系统持久化、返回菜单和完整用户态启动是其他验收点。

## 9. 复现本轮检查

以下路径假设在本独立检出根目录。`out/`均为忽略的本地产物，不提交镜像或厂商二进制。

主机源镜像绑定：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/audit_fuxi_twrp_port.py \
  --image /Users/zhuxiaocheng/Downloads/twrp-3.7.1_12-v9.0_A16-fuxi-skkk.img \
  --output out/twrp-port-evidence.json
```

主机损坏输入检查，直接编译生产C文件，fixture CRC由独立Python zlib生成：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/test_fuxi_data_port.py \
  --edk2 /Volumes/External/VSCode/UniXNU/uefi-fuxi/Mu_Basecore \
  --report out/data-port-m0-host-tests.json
```

M1 原生 UFS 核心的建模控制器主机测试（UTRD/UPIU、轮询与隔离、响应/sense、停队列计划、SMMU 计划器、SHA-256 向量对 hashlib）：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/test_fuxi_ufs_port.py \
  --edk2 /Volumes/External/VSCode/UniXNU/uefi-fuxi/Mu_Basecore \
  --report out/data-port-m1-host-tests.json
```

容器内独立模块编译，避免修改或构建其他会话的候选：

```sh
docker exec -w /work/ramdisk-test/uefi-twrp-data unixnu-fuxi-build-arm64 \
  /work/build-support/venv-arm64/bin/python3 tools/build_fuxi_data_port.py \
  --edk2 /work/uefi-fuxi/Mu_Basecore \
  --output /work/ramdisk-test/uefi-twrp-data/out/data-port-m0-no-smc
docker exec -w /work/ramdisk-test/uefi-twrp-data unixnu-fuxi-build-arm64 \
  /work/build-support/venv-arm64/bin/python3 tools/build_fuxi_data_port.py \
  --edk2 /work/uefi-fuxi/Mu_Basecore \
  --output /work/ramdisk-test/uefi-twrp-data/out/data-port-m0-scm-query --scm-query
```

`DataPort.dsc`独立编译两个DXE模块，不产生FD/Android启动镜像。其依赖使用现有Mu_Basecore，脚本不修改共享EDK2或应用补丁；输出build.json记录源哈希和真实退出码。模块变体顺序构建，共用本独立检出的Build目录，不得同时运行。

M1 候选（receiver-only + 原生 UFS 诊断）在容器内构建，`--base` 必须是实验检出 `ramdisk-test/unixnu-source`（其 bootimg.py 才支持 v3 头与 os_version；顶层 unixnu-source 的旧 bootimg 会在 verify 处失败）：

```sh
docker exec -w /work/ramdisk-test/uefi-twrp-data unixnu-fuxi-build-arm64 \
  /work/build-support/venv-arm64/bin/python3 tools/build_fuxi_ufs_candidate.py \
  --base /work/ramdisk-test/unixnu-source --device /work/ramdisk-test/UniXNU-fuxi \
  --edk2 /work/uefi-fuxi/Mu_Basecore \
  --output /work/ramdisk-test/uefi-twrp-data/out/ufs-m1-receiver
```

本检出的四个子模块需先按 pin 的 SHA 就位（本地引用顶层 `uefi-fuxi` 的对象即可，无需网络）。候选定义的开关：`FUXI_USB_RAM_RECEIVER=1 FUXI_USB_TRY_SID_ROUTE=1 FUXI_USB_KEEP_PHY=1 FUXI_PAYLOAD_DIAGNOSTIC=0 FUXI_USB_RAM_SYSTEM_HANDOFF=0 FUXI_DATA_PORT_UFS=1 FUXI_DATA_PORT_PROBE=0 FUXI_DATA_SCM_QUERY=0`。

本次模块哈希：

```text
no-smc  12800字节 d0b54e2fda7c01d25db5d6d858ea4ad564819bde13ac58f295a128d4e9eaffd1
query   13824字节 90ad4c5e4a3e8022292ced90636ca1545d4758986e7461622b3d8ddd48286baa
```

后续若生成完整候选，需在其独立构建上下文中设置上述开关；设备仓库现有`build-fuxi-usb-ram.py`没有这两个CLI参数，不要臆造命令。继续保留USB的`--try-usb-route --keep-phy`，系统交接时保留`--system-handoff`，系统payload仍须用规定打包器并带`FUXIPAYL`。该阶段尚未构建或验证。

## 10. 上机与后续工作记录

上机前检查设备互斥和`fcde91e`、product/unlocked、profile及SHA256。仅允许`fastboot boot`，不flash、不擦除、不改slot、不运行TWRP安装脚本。每次使用新的attempt目录；接收器窗口存在时不得以fastboot列表为空为由重启。

新组合镜像仍须完成工作区要求的SMMU、route、receiver和image四项检查；进入系统挂载阶段时补齐候选套件。主机和实机检查按工作区规则执行，实机结论入档前所有必需检查必须退出0。

本轮M0没有组合镜像或attempt；`out/data-port-m0/REVIEW.md`记录M0模块构建和未验证边界。M1原生UFS只读适配已实现并通过建模控制器主机测试与ARM64编译；其实机证据（空闲控制器、独立DMA窗口、SID路由readback、GPT与原始块哈希照片）待receiver-only候选`out/ufs-m1-receiver/`完成规范四项检查后上机采集，不得宣称默认固件已有可供探针使用的UFS BlockIo。

后续每阶段更新本表和候选REVIEW，并向设备仓库`diagnostics/ram-root/usb-bulk.md`追加结论。UEFI分支只推送`origin feat/twrp-data-uefi`至mouse233/uefi-fuxi，设备仓库的独立诊断追加按其既定fork/分支规则提交。

## 参考接口

- [Linux v5.15 F2FS磁盘格式](https://github.com/torvalds/linux/blob/v5.15/include/linux/f2fs_fs.h)：本轮只使用公开字节布局事实；未移植完整文件系统实现。
- [Linux v5.15 SCM接口](https://github.com/torvalds/linux/blob/v5.15/drivers/firmware/qcom_scm.c)：调用存在性查询和ABI探测参考；ES具体命令以输入TWRP模块为准。
- [Android FBE](https://source.android.com/docs/security/features/encryption/file-based)、[元数据加密](https://source.android.com/docs/security/features/encryption/metadata)、[硬件包装密钥](https://source.android.com/docs/security/features/encryption/hw-wrapped-keys)：区分文件、元数据及硬件密钥处理。


## 2026-10-26：上游合并与 WSL 构建入口

本分支已合入包含上游 5493eb07 的 fuxi 主分支，保留已验证的 RAM/FD
布局、受限载荷/SEC 检查、UFS 小端 PRDT 和默认关闭的诊断开关。
上游独立 loader/extents 路径不接入当前 USB/M1 接力；其扫描器不自动调度。

当前容器仍名为 `unixnu-fuxi-build-arm64`，实际宿主是 amd64，固件目标
固定 AARCH64。两个构建器接受 amd64/ARM64 Linux 宿主；容器 Python
使用 `/opt/fuxi-venv/bin/python3`，不再使用迁移包里的 macOS/ARM64 venv。
`build_fuxi_data_port.py` 同时归档两个 DXE 模块、哈希与宿主/目标架构。

新独立构建 `out/upstream-sync-ufs-m1-receiver/REVIEW.md` 记录完整平台/
镜像编译、六项交付检查与未上机边界。模块 no-SMC/query 两版及完整固件
真实退出 0；原生 UFS 两版均无 SMC，M0 版本分别 0/1 条 SMC。
主机检查不替代 M1 GPT/magic/SHA256/停机数值块照片。

新框架主分支已纳入 bootimg v3 元数据修复，§9 关于“顶层旧版 bootimg”
的描述仅适用于 2026-10-25 快照。主分支与实验分支仍需区分：本轮 M1
使用合并后的 `feat/ramdisk-test` 基础和原有设备仓库，不用旧包覆盖它。
