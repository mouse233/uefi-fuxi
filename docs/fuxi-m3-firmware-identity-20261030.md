# M3 当前 slot A 固件身份核验（2026-10-30）

用户确认已进入TWRP后，只读核对当前手机的slot及ABL/TZ哈希。**当前slot A的
ABL、TZ均与本地PixelOS包中的对应固件匹配**，因此可以使用包内SDK与新的ABL A
作为后续代码分析输入。历史ABL B与当前ABL A确实不同，不能混用地址。
本轮没有锁定-62返回PC、取得运行时boot槽值或通过M3；没有发送新的安全命令。

## TWRP 实际采集

2026-10-30 **22:31:38 Asia/Shanghai**，设备fcde91e/recovery/fuxi/root，
ro.boot.slot_suffix=_a、release17、TWRP版本3.7.1_12-Xiaomi13_v9.0_A15。
固定libqtikeymint.so哈希仍为657093d0…b1ddcb。采集前互斥检查无活动传输/启动任务；
沙箱中的ps被限制后，在获准的只读沙箱外检查退出1且无匹配输出，再操作ADB。

两轮设备端sha256sum读取固定四个固件分区，身份、启动连续性标记、库哈希、
分区映射/几何在前后稳定。连续性UUID只在内存比较，不写报告。总计设备内部
哈希50331648字节（48MiB），传回摘要，**原始固件字节传输0**。没有读userdata/
metadata、进程内存、日志、口令或密钥材料，也没有挂载/remount、重启或切槽。

| 分区 | 字节数 | SHA256 | 对照 |
| --- | --- | --- | --- |
| abl_a | 8388608 | `eddd52b961aea860ed7a04f27b4e6f7976e04ee30ca1113b0e3b867aa919431d` | 本地ROM ABL补零后匹配；不同于历史abl_b |
| abl_b | 8388608 | `78595f9a5fbaba528b894fa7f3991db37fe1bcd03be3036e5cb3c254405655f3` | 与2026-10-22保存的abl_b一致 |
| tz_a | 4194304 | `072574e20b5f00aad08a4da503b5ee1d64c1edda370b3b1bcb6b799cdbc79fd3` | 本地ROM TZ补零后匹配 |
| tz_b | 4194304 | `e4b39c030e17c7294adfcc2f7fe07218973851ea3e8c3ea900b876a5602b8207` | 不匹配本地ROM TZ补零对照 |

采集报告all_references_match=false反映上述四分区对“历史ABL B＋ROM TZ”两份
原始参考的比较，不是采集失败，更不是slot A固件不匹配。后续独立审计闭合了
**abl_a＋tz_a**与ROM的关联；slot B差异保留原样，没有切槽或更换固件。

证据是当前分区内容及slot属性，不是对安全世界已加载RAM的证明，不能排除
加载环境、服务返回值或TA实例生命周期上的差别。

## 当前 ABL A 单独提取、绑定和重核验

固定ROM manifest SHA仍为cc48764e…95b146。包内ABL仅233472字节，SHA为
adfb733e…45e59c；补零到8388608字节后与本轮abl_a的全分区哈希一致。
从该本地文件有界解压0x1060的GUID-defined LZMA段，不从手机导出原始固件。
展开1134792字节，其中PE节偏移184、PE长度1134592，SHA为：

```text
48de0c341840c30e99d483ebbbdc0df4de67bc971d76bd05477587ace87aab3b
```

当前PE与历史B的b5ccae26…16e954不同，本轮未覆盖或改动历史二进制/审计。
使用单独固定的新地址：

| 当前ABL A代码 | 地址 |
| --- | --- |
| 镜像头回退片段 | 0x2cd24 |
| 回退字段准备完毕 | 0x2ce68 |
| 启动状态入口调用 | 0x2d0d0 → 0x41d28 |
| 208请求构造片段 | 0x41f60..0x41fb0 |
| QSEECom发送跳板 | 0x423e0，未执行 |
| 请求常量 | 0xa9da0：[0x208,0,16,48] |

两份旧A/B候选镜像完整SHA重新固定；它们都保留头0x220001a7，即17.0.0/2026-07。
在当前ABL A中**明确进入头回退片段**，再经公开合成记录的真实构造片段、固定TA
真实边界解析与日期转换，均得到OS170000/boot202607。合成带日字段额外控制得到
20261005；它不是向手机设置boot参数。

共10组主机控制通过：2候选链、3坏版本拒绝、2旧/新头格式、1合成日期链和
2外部服务入口拒绝。仍在QSEECom发送前停止，TA在404b4前停止；先前ROT、
平台门控与SDK服务没有执行或以成功替代。**实际来源选择、boot运行值和ABL→UEFI
TA实例延续仍未观察到**，所以不能把202607写成此前实机-62的已证根因。

TZ的本地3973120字节SHA为d4b8afbe…60d418，补零到4194304字节后与tz_a匹配。
前轮三个SDK定义符号因此有了当前slot A分区版本依据；该证据不等于完整SDK
初始化执行、实际对象服务结果或密钥恢复成功。

## 检查、复现与下一门槛

采集器16组模拟检查通过：固定身份/几何/库异常在固件哈希前停止，格式错误、
传输失败、固件/启动/库/几何竞态拒绝；稳定但不同的固件作为差异证据保存。
两份旧候选各91文件源码绑定仍完整，无新固件，不需重跑无关固件资格。

```sh
python3 tools/test_fuxi_m3_firmware_identity.py \
  --report out/m3-firmware-identity-v1/host-tests.json
python3 tools/collect_fuxi_m3_firmware_identity.py --serial fcde91e \
  --abl-reference /Volumes/External/VSCode/UniXNU/boot-tests/2026-10-22-stage-markers/private/abl_b.img \
  --tz-reference out/m3-boot-provenance-audit-v1/rom-tz.img \
  --output out/m3-firmware-identity-v1/twrp-firmware-identity.json
/Users/zhuxiaocheng/.pyenv/versions/3.12.3/bin/python3 tools/audit_fuxi_m3_active_firmware.py \
  --archive /Users/zhuxiaocheng/Downloads/PixelOS_fuxi-17.0-20261024-0342.zip \
  --partition out/m3-date-support-v1/keymaster-partition-verified.img \
  --identity out/m3-firmware-identity-v1/twrp-firmware-identity.json \
  --candidate-a out/m3-configure-context-a-v1/Mu-fuxi-usb-ram.img \
  --candidate-b out/m3-configure-context-b-v1/Mu-fuxi-usb-ram.img \
  --output out/m3-firmware-identity-v1
```

采集器拒绝覆盖既有证据；复采需要新输出路径和设备互斥。host audit用既有
Unicorn/Python在沙箱外私有内存运行，不安装依赖。厂商二进制留在忽略的out。
规范证据：[TWRP身份](evidence/fuxi-m3-firmware-identity-20261030.json)、
[当前固件审计](evidence/fuxi-m3-active-firmware-20261030.json)、
[采集器检查](evidence/fuxi-m3-firmware-identity-tests-20261030.json)。

下一门槛转为**已匹配SDK的服务调用与TA实例加载/卸载链**。当前slot A版本
身份缺口已补齐，实际初始化状态、同轮公开字段及-62分支仍缺证据。M3/M4/M5未
通过；不据局部结果设置boot、拼造启动状态、试发208/setVersion或放宽隔离。
