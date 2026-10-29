# Keymaster TA 对 0x3121 的命令分派复核（2026-10-29）

## 实机结果与固定输入

候选 a4fa6e2e…5594c31 的照片显示 `set-version` SMC a0..a3=0，响应
`status=FFFFFFD8`、`payload=9FF0`，探针返回 Device Error 并保留对象与桥。
只读导出的 keymaster_a 为 524288 字节，SHA256
`2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6`。

## 对 TA 代码的受限执行

`tools/audit_fuxi_m3_ta_dispatch.py` 限界加载该固定 ELF 的 program headers，
执行其 VA 0xb0b4 请求头处理、0xb2a0 分派器、0x2a700 数量函数与 0x2a710
表地址函数。模型只提供日志、时钟、内存清零和初始化状态桩；为 Unicorn 不支持
的 PACIB/RETAB 建模控制流，不验证签名。无安全世界或手机调用。分派器取表地址
0x5a5e0 和数量89，逐条按16字节比较命令；查无命令时走 VA 0xb344，返回 -40。
0x3121 扫描89项未命中，最终响应头为 `d8 ff ff ff f0 9f 00 00`，与照片所示
status/payload 相同。对照：0x200 在第19项命中，0x3120 在第18项命中；初始化桩
返回 false 时不扫描并返回 -1000。不得把 0x3120 当作 0x3121 的替代，尚未核验其语义。

这为“0x3121 未列入这张 TA 分派表”提供很强的原因线索；由于初始化及外部调用是桩、
没有 TA 真实运行轨迹，不能证明实机走了这一分支，也不能从状态声称其余安全世界状态。

## PixelOS 本地 OTA 对照与限制

本地 `PixelOS_fuxi-17.0-20261024-0342.zip` SHA256
`a281cb54326139de8e6a285e5d4165456b08fc1f546b2e44dd18b50ba401a9c0`；
使用 payload-dumper-go 上游 c3a50ba8d784764c06143c1f82971cd81a77f9d6，
保留 payload 校验，提取 `keymaster`、`vendor`、`system`。OTA keymaster 为409600字节，
SHA256 `61b45016eba26d3e9c4e1dcca5238420847a49618cd8030591f04971f91da480`；
与手机 keymaster_a 的前409600字节逐字相同，手机分区剩余部分为零。
OTA vendor 镜像 SHA256 `ed3efaed2b884aa47bc86a3a8d3a38723430b83a081bb291bec4f10f2ef06b17`；
system 镜像 SHA256 `3d007d7278f64ce11a798c91faaa6f20c4e3ba99ab362d5ecf1e89256800d338`。
这些是更新包里的文件，不代表手机当前 system/vendor 已经与其逐字一致。

OTA vendor 的 libqtikeymint SHA256 `368b34db8efee95d1713cee10d823e8572f6668ef559867c67e292dc3b9e8c52`，
其 setVersion/configure/serializeInteger 代码区间与此前 TWRP 固定库对应区间相同；
deviceutils SHA256 `1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2`、
qcbor SHA256 `bda86553e45dce1da186830619909b3bae95ff9a91ce3a5df94fa0801c8b2500`
与之前固定库相同。`tools/audit_fuxi_m3_vendor_configure.py` 在隔离模拟中对比
setVersion 返回0/-40、后续 send 返回0/-28：非 legacy configure 均继续调用
命令0x2116，函数最终返回后续 send 的状态。这不证明实机已执行配置，不等于允许
本诊断忽略其失败，更不证明调用配置安全或可回滚。

OTA system 属性 `ro.build.version.release=17`、`ro.build.version.security_patch=2026-10-01`；
vendor 属性 `ro.vendor.build.security_patch=2026-08-01`。固定 TA 的 0x2116 处理路径
对三个类型化字段 `0x300002c1`、`0x300002c2`、`0x300002ce` 调用写状态的函数，
其持久性与安全世界副作用尚未完全验证。不能将 OTA 属性当作当前系统状态，更不能
推测填值或通过绕过原失败保护宣称修复。

## 下一步与准备好的只读采集

手机返回 Android 后，用 `tools/collect_fuxi_keymint_context.py --output <独立路径>`
确认互斥、ADB serial 与 fuxi，并只读取非秘密系统属性和四个 vendor 库 SHA256；
不获取密钥、不写设备、不重启。模拟 ADB 成功与错误机型拒绝均已验证。
据实际属性和库哈希与 OTA 逐项对照，再研究厂商序列化、配置初始化副作用及独立候选；
不发送未知参数，不改之前 0x3121 失败后的保留策略。当前没有构建新的上机候选。
