# M3 public configure A/B 候选（2026-10-30）

B线 UEFI 层，独立目录 `out/m3-configure-context-a-v1` 和
`out/m3-configure-context-b-v1`。两份候选已构建、完成主机资格，尚未上机。
本轮没有ADB、fastboot、设备重启或设备状态变更。

## 唯一实验变量与交付

| 项 | A：Android 日期基准 | B：当前 TWRP 公开属性 |
| --- | --- | --- |
| OS version | 170000 | 170000 |
| OS patch / vendor patch | 20261005 / 20261005 | 20991231 / 20991231 |
| 镜像字节数 | 1,888,256 | 1,888,256 |
| 镜像 SHA256 | `169e7401d2fa3fcce8347f50232b253c11bf884773b474fb2365b3b52185e44b` | `81e1abd43ec63d27abd970be69943557d388b61e72ce6274f1684b9a977474f5` |
| 完整主机资格 | 29/29 exit0 | 29/29 exit0 |

两者同版91文件源码、同一board pin
`1d071dae4618b0676d313cfbe1fc39689e6f139e`、框架revision
`7e237de0aa81a8f38221134c752af2d71236cddc`及同字节的复制框架脚本。
框架检出预先有dirty状态，未清理或提交它；差分检查比较实际复制脚本，不能把
revision相同当作工作树相同。board唯一差异为`FUXI_M3_CONFIGURE_PATCH`。
两者共用新证据pin/tag，A不是旧v3的位相同重打包，而是本版源码上的对照组。

调用链均为原生UFS只读准备 → 停队列 → root/open122/load64/getVersion →
一次public configure → 既有密钥恢复 → 验证闭合后擦除输出/收尾 → PARK。
`FUXI_M3_CHARACTERISTICS_PROBE=0`，不在-33后继续begin，也不依赖之前保留的会话。
没有generate/upgrade/setVersion、convert/HWKM/ICE/DUN或userdata解密接线。
配置失败或恢复被隔离/完成状态不明时仍保留注册范围、禁止续调，不能为了比较
日期放宽任何停机门。

## 公开字节与证据绑定

`audit_fuxi_m3_configure_profiles.py`在已有Unicorn私有内存中执行固定厂商编码器
和TA公开解析器。每组6种参数顺序与厂商字节一致，6个合法/7个非法解析用例通过；
合计12组厂商匹配、26项TA解析。没有真实blob、密钥、SMC或安全服务调用。

新证据`evidence/fuxi-m3-configure-profiles-20261030.json`的SHA256：
`3cc89865a2f0de0298ef9fa5c2c593be7f8770594afb2f990cf0e1bff53f1320`。
它同时绑定原始实机-64/configure证据`817bc13d…6c2c32`和本轮TWRP上下文
`e6d10b44…cf4a42a`；未改写旧pin。构建器只接受精确证据与两种日期，旧证据
仍只允许20261005。11项门控测试拒绝篡改、截断、任意日期及旧证据启用2099。

请求为`0x2116`加CBOR，三字段顺序固定；两组仅两个日期整数不同：

```text
A 16210000a416031a300002c11a000298101a300002c21a0135288d1a300002ce1a0135288d
B 16210000a416031a300002c11a000298101a300002c21a01404cff1a300002ce1a01404cff
```

每组27项ASan/UBSan生产配置/恢复入口用例核对实际提交字节及异常保留分支。
完整资格还包括普通入口17项、交换层默认关闭/启用/探针模式、55项恢复后端、
实际AARCH64引用/链接map、默认/query模块SMC计数、M0/M1/M2、USB/SMMU及
交付FD/EFI/镜像/源码绑定。实际EFI含本组请求、无另一组请求或特性探针入口。

可提交差分结果：`evidence/fuxi-m3-configure-pair-20261030.json`。
详细原始报告、四段构建退出码、29段资格退出码、REVIEW和提交源码绑定都在各自out目录。

## 复现与实机观察边界

构建必须顺序进行：A完整固件→默认/query模块→资格，完成后才开始B同样四段。
共享`Build/fuxiPkg`的实际对象会被下一次固件构建覆盖；各候选资格阶段已独立归档，
不要在B构建后用当前Build对象重新给A背书。

```sh
docker exec -e PYTHONDONTWRITEBYTECODE=1 -w /work/ramdisk-test/uefi-twrp-data \
  unixnu-fuxi-build-arm64 /work/build-support/venv-arm64/bin/python3 \
  out/m3-configure-context-a-v1/run-build-checks.py
# A完整四段退出0后，才对b-v1运行同目录脚本。
python3 tools/check_fuxi_m3_configure_pair.py \
  --a out/m3-configure-context-a-v1 --b out/m3-configure-context-b-v1 \
  --report out/m3-configure-context-a-v1/pair-checks.json
```

下一步需两次独立临时启动并拍照，先A后B，不自动串联、不复用失败会话。
每次仍须确认设备互斥、fcde91e/fastboot/product fuxi/unlocked yes/slot_a及
镜像SHA；各目录`attempt-01/boot-ram-window-once.py`固定本组镜像、源码提交、
91文件、29项资格和证据，`--verify-only`不发设备命令。只允许`fastboot boot`。

照片需保留UFS停止/doorbell、configure三个公开值/状态、恢复state/stage/km/
bytes/retained/commands/resumes/response-header和最终PARK；只记录长度/状态，
不记录口令、密钥、明文、材料前缀或摘要。成功取得恢复输出也只代表局部密钥
恢复证据，候选会擦除输出，仍不包含ICE/DUN和userdata已知块明文哈希。

当前属性不是构造时采样证据，两种日期均被离线解析接受也不证明会解除实机-62。
历史FSR400、-33和-62的具体根因未解决；不得由A/B差异唯一归因旧格式或某个
版本字段。M3、M4、M5均未通过，无免USB重传声明。

## A attempt-01 临时启动（17:00，等待照片）

用户进入fastboot后，互斥、fcde91e/product fuxi/unlocked yes/slot_a及下载容量
核验通过，91文件/源码/镜像/29项资格复核通过。仅临时启动A一次：Sending0.040s、
Booting1.889s、总1.930s、exit0；无分区写、slot变更或重试。
原始记录在A目录attempt-01/device-test.json，可提交摘要见
`evidence/fuxi-m3-configure-a-attempt01-20261030.json`。没有照片，尚无UFS停机/
configure/恢复/PARK结论；B未启动，M3/M4/M5未通过。
