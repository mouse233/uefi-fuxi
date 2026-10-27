# M2 metadata-files v1 attempt-01 — 2026-10-26

## 结论

**UEFI 实机完成 metadata 根目录遍历、目标路径查找和首个 inline 普通文件的完整读取及 SHA256，UFS 队列停止正常，进入预期 pre-USB 诊断驻留。**
这不是 Android 解密、非 inline 文件读取、独立 TWRP 对照或完整 M2 验收通过。

## 启动与输入绑定

互斥检查无其他设备任务；Windows PnP 正常识别 Android Bootloader Interface，
具备设备访问权限的 fastboot 确认 fcde91e。最初沙箱内设备列表为空，不代表物理设备缺失。
适配器再次核验 serial/product=fuxi/unlocked、usb-ram profile、Android boot v3/
os_version=0x220001a7、候选十二项检查及精确 SHA 后，仅执行一次 fastboot boot。
2026-10-26T22:49:51.566129+08:00 完成；Sending OKAY 0.059s、Booting OKAY 1.840s，退出0。
无 flash、擦除、改槽、载荷传输、重启或重复启动。

- 镜像 SHA256：`cf28d6375ae7a321334fa789ef996a7f7a8e72df2a806bde9d5e9453160cf009`。
- 实际源码：`6bcce79e08675dd732e72fdf3433a6566ee7fcb3`，49项绑定一致。
- 原图：`M2-first-file-original.jpg`，SHA256 `52b44e06e613dbb300ba42c7989c4e5543e85c40e455d61b323fe5b6cca3717b`。
- 原始主机操作保留在 `device-test.json`；逐项判读在 `assessment.json`。

旧 Windows single-boot 适配器只接受 receiver_only=true；本次建立独立 M2 适配器，
要求 diagnostic_only/m2_metadata_files/park=true、receiver_runtime_enabled=false，
保留其他身份/profile/SHA/镜像检查，没有伪造原 verification.json 的 receiver_only 字段。

## 照片观察

- M1 NOP/power-query/wake-SSU/TUR/capacity/GPT 成功；4096字节块，
  metadata=4000..7fff，userdata=2f7840..3afc3fa。
- metadata/userdata 均 independent-read-proof=Success、reads=3/3、distinct-buffers=1。
  首块 SHA 与 v8 attempt-01 相同：metadata e77426cf…e51d，userdata 890d7f62…be33。
  这是同次启动的读取证明，屏幕中的缓存重放不另计读取。
- `watchdog-disable=Success`，`prepare=Success`，selected-pack=2、cp-flags=0x145、
  feature=0x499、cp-version=0x5788ea72、journal=0。
- `root-open=Success`、`root-list=Success entries=13 limit=16`，含 . 和 ..，以及
  aconfig、vold、password_slots、bootstat、ota、watchdog、tradeinmode、prefetch、
  apex、staged-install、gsi；所列项 clipped=0。
- `lookup=Success path=/vold/metadata_encryption/key/version`。
- 文件 nid=69、bytes=1、inline=1；`file-read=Success bytes=1`。
- SHA256：`6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b`。
- 主机独立计算 SHA256(b'1') 与该摘要一致；这是对摘要含义的核对，**不是 TWRP 读取证明**。
- UFS `stop=1 db=0 run=0 hcs=0x10f is=0 tdb=0`；final stage=shutdown、
  poisoned=0、ready=0、smmu-configured=1。GFSR=0，FSR=0x400；未宣称完整路由恢复。
- 最终 `file-result=Success; decrypt=UNIMPLEMENTED handoff=0`，
  `FUXIM2 PARK: no USB receiver; no handoff`。未见报告 dropped/truncated 警告。

## 验收边界与下一步

1. 本轮实机成功的是 1 字节 inline 文件。非 inline 内容读取与直接/间接节点的数据
   映射仍只有主机证据，不能用本照片推广为大文件读取已通过。
2. 所选 checkpoint 的 NAT journal 为0；非空 journal 覆盖实现只有主机样本证据。
3. 仍需 TWRP 对目标文件大小/SHA、metadata/userdata 首块做独立同状态对照。
4. 下一项实机应选择已确认存在的非 inline 文件，先取得 TWRP 大小/SHA，随后读取
   完整内容并比较；不为让测试成功而创建或伪造设备上的 version 文件。
5. 没有 Android 解密、ICE/QSEE/密钥解封、RAM 对象加载或 XNU 交接。本候选提前驻留，
   没有重新测试或修复原 USB 枚举/停止故障。驻留不是自动返回 Android。

USB 接收器未启动的判断依据为交付镜像配置、入口驻留代码顺序与 PARK 标记；本轮未做独立主机 USB 抓包，不把此判断当作 USB HALTED 或故障修复证明。

## 2026-10-27：A17 TWRP 独立对照

新 TWRP 下目标 `version` 文件大小 1 字节，完整 SHA256 与上文 UEFI 结果相同；
metadata 首块 SHA256 也与 UEFI 相同。TWRP 当时以 rw 挂载 metadata，
故对照证明该文件及首块在两次观测中一致，不扩大为卷完全静态。
userdata 原始首块 SHA256 已变化，原因未定位。M2 的 inline 文件设备读取
得到独立参考验证；非 inline 文件和非空 journal 仍无设备通过证据。
详见 [A17 TWRP 静态与实机报告](fuxi-twrp-a17-static-20261027.md)。
