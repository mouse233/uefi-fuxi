# M3 boot/context 与访问器索引核验（2026-10-30）

**索引0已取得映像与重定位证据；实机boot=0仍未证明。** 固定TA的版本访问器
GOT项指向只读常量0；GetVersion及三字段configure均不设置boot patch。但加载入口
先调用外部SDK初始化，这些代码不在当前已固定输入中，不能从映像默认boot0推断
初始化后的实际值。本轮没有形成新的固件修复或实机-62返回PC结论。

用户本轮选择仅完成离线核验。此前一次互斥检查无活动任务，ADB devices退出0但
列表为空，没有读取手机文件；用户选择离线后没有再访问手机。工作区也未找到
libcmnlib/cmnlib固件副本。未重启、发送安全命令、生成/升级或写回。

## 1. 访问器索引：不再用可写合成变量代替映像常量

固定TA SHA256仍为
`2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6`。
直接解析PT_DYNAMIC/DT_RELA，而非依赖缺失的section重定位表：

| 项 | 已验证值 |
| --- | --- |
| GOT地址 | 0x5a308 |
| 重定位类型 | R_AARCH64_RELATIVE（1027）、symbol0 |
| addend/目标VA | 0x4c544 |
| 目标整数 | 0 |
| 目标PT_LOAD权限 | R E，非W |

273个RELATIVE项已按加载基址应用到私有模拟映像；其他4个ABS64与1个GLOB_DAT
保留未解析状态，不执行依赖它们的外部初始化。目标RX区域按ELF声明设保护，
实际STR指令尝试改索引被WRITE_PROT拒绝。该控制证明模拟器遵守这一加载布局，
**不替代**实机安全加载器的重定位/保护回读，也不把该整数命名成已证实的Binder
client ID或协议版本。此前client0假设现有了固定映像的默认值依据，实际SDK/加载
环境仍未完整覆盖。

模拟执行b490的本地入口仅观察到ready标记写入，boot值不变；不把日志桩返回值
当作完整TA初始化成功。然后在原重定位索引上执行A/B公开configure和四个真实
getter，结果分别为：

```text
A: OS170000 / OS patch202610 / vendor20261005 / boot0
B: OS170000 / OS patch209912 / vendor20991231 / boot0
```

这是“本地入口＋公开configure，未运行外部SDK”的结果，仍不是手机实际boot值。
两个控制均未写5b4f4，也未改索引。

## 2. GetVersion与setVersion不能混同

固定表项0x200（十六进制，十进制512）指向ddf4，是版本查询。私有模拟响应容量
20/64时返回0和[4,1,4,1012]，容量19时返回-29；三组均未改boot或索引。
它不是给boot上下文赋值的接口，也不能与旧setVersion路径中的十进制200（0xc8）
混同。该固定TA表中没有0x3121或0xc8；不因初始化尚有缺口而重发此前失败命令。

## 3. boot字段从独立处理链写入，不由configure填充

固定表项0x208指向bb7c。本地可见的处理顺序包含：

1. 平台状态查询（194fc，未执行），然后检查5ba58的一次性标记。
2. 输入长度与31f10处理链、输出记录长度检查（未执行/未替代成功）。
3. 从处理后的记录+28/+2c读取位域，换算OS与boot日期，复制48字节上下文。
4. bde0先写标记，bdf4写5b4f4，再调用404b4继续处理。

因此208会改变TA状态，不能称为只读查询；局部写标记后尚有后续调用，也不能由
片段执行到此便认为完整初始化或失败后的回滚已经成立。两个门控片段控制确认：
标记0走输入检查，标记1走已设置分支；它们同样没有执行此前的平台查询。

本轮只进入**处理后的转换片段bcf8..bdf8**，使用私有合成48字节记录，精确有界
memcpy被建模；在后续404b4调用前停止。七组真实转换指令控制通过：

| 合成字段 | 转换值 |
| --- | --- |
| OS17.0.0、2026年10月、日字段0 | OS170000、boot202610 |
| 同上、日字段5 | OS170000、boot20261005 |
| OS16.1.2、2026年10月、日字段0 | OS160102、boot202610 |
| 2000年1月、日字段0 | boot200001 |
| 2127年12月31日 | boot21271231 |
| 合成月字段0 | 片段仍得到202600；不证明完整请求接受无效日期 |
| 改变私有记录地址 | 转换不变 |

这说明当前blob的boot202610与该位域转换语义相容，不能证明TWRP实际使用了哪份
启动记录，也没有构造/认证/发送真实208请求。未知真实记录的来源、权限和生命周期
不能靠按blob字段拼造参数来代替。

## 4. TA加载入口中的外部初始化仍是证据缺口

按JMPREL/SYMTAB/STRTAB解析，CElfFile_invoke的加载路径包含：

```text
cmnlib_init → GPAppLib_init → 构造器数组 → GPAppLib_appInit → 本地b490
```

固定映像的构造器数组begin=end=5ab70，数组为空；但三个外部SDK入口仍会被调用。
本轮没有它们的已固定代码，没有执行或用返回成功替代它们，因而不能排除SDK或
加载环境对启动上下文的影响。boot映像初值0、空构造器数组和本地b490不写boot，
共同仍不足以证明实际完成加载后的boot=0。

## 5. TWRP初始化链：能确认顺序，不能补出未捕获的boot记录

引用既有展开档的init.recovery.qcom.rc，与A17证据中的SHA逐字节匹配：
`ea0049522493a2f2175d9f1c93a8ebaffea1f650da6ae4c9c54da041f2a10f1c`。
确认qseecomd先启动，listeners.registered=true后才启动KeyMint。
固定libkeymasterdeviceutils.so SHA
`1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2`：

- 61c8的构造器等待同一listeners属性，再从/vendor/firmware_mnt/image尝试
  keymaster64、回退keymaster，随后请求0x200版本。
- 名为KeymasterUtils::initialize的66c0只有BTI、返回0、RET，是空实现。
- 库/启动脚本的这些事实不构成TWRP发出208、使用某份boot记录或实际TA槽值的轨迹。

因此不能把“服务已启动”或“initialize返回0”替换成boot上下文已核验。
现有主机没有对应cmnlib副本，本轮也没有可用ADB文件读取及运行轨迹；外部SDK与
具体boot参数提供者保持未验证，不猜测已由Android、ABL或加载器中的哪一方设置。

## 检查与交付边界

审计工具tools/audit_fuxi_m3_boot_client.py：2组configure、3组GetVersion、7组局部
转换、2组一次性门控、4组写保护/SMC/循环/输入修改边界控制全部通过；另绑定
ELF布局、重定位、表项、库字节和A17匹配脚本。原A/B各91文件源码绑定仍完整。
只新增主机工具和文档，不改固件，不重建或重跑无关固件资格。

精确脱敏结果：
[evidence/fuxi-m3-boot-client-audit-20261030.json](evidence/fuxi-m3-boot-client-audit-20261030.json)。
原始汇编、ELF表和REVIEW位于out/m3-boot-client-audit-v1。

```sh
/Users/zhuxiaocheng/.pyenv/versions/3.12.3/bin/python3 tools/audit_fuxi_m3_boot_client.py \
  --partition out/m3-date-support-v1/keymaster-partition-verified.img \
  --deviceutils out/twrp-a17-analysis/ramdisk/vendor/lib64/libkeymasterdeviceutils.so \
  --ramdisk-reference /Volumes/External/VSCode/UniXNU/boot-tests/2026-10-25-twrp-skkk-data-readonly-analysis/ramdisk-files \
  --output out/m3-boot-client-audit-v1
```

使用已有Unicorn/Python，在沙箱外私有内存执行；没有安装依赖。boot/client的
映像默认值与数据流现已更明确，实机初始化链和实际-62返回点仍缺证据。
下一门槛是补齐匹配SDK或可信同轮初始化轨迹；不凭局部控制去设置boot字段、
重发208/setVersion或放宽隔离。M3/M4/M5及免USB重传均未通过。
