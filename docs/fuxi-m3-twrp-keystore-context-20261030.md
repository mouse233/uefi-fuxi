# M3：TWRP 实际上下文与 keystore2 中间层差异（2026-10-30）

B 线 `feat/twrp-data-uefi`。接特性隔离候选的实机停点：-33 后跳过 begin、
attempted0/retained1、PARK。用户随后自行进入 TWRP 并明确授权读取。
本轮只修改主机采集/审计工具，不修改 UEFI 或打包，不构建或启动新镜像。

原始包为 `out/m3-twrp-context-audit-v1/`，结果与边界见其 `REVIEW.md`。
可提交的非秘密证据汇总为
[`evidence/fuxi-m3-twrp-keystore-context-20261030.json`](evidence/fuxi-m3-twrp-keystore-context-20261030.json)。

## 实机读取与稳定性

ADB 确认 fcde91e/recovery、fuxi、root、slot_a；TWRP 的版本字符串仍含
`3.7.1_12-Xiaomi13_v9.0_A15`，不能用此字符串否定 release=17 的已验证参考。
通过三个进程的 executable SHA256、四个库的文件 SHA256、KeyMint 进程实际映射路径，
核验当前输入确实与固定参考匹配；进程 PID/start ticks、可见库集合与属性均做两次
稳定性检查。没有读取完整进程内存、密钥文件、口令、token 或解密后的文件内容。

| 项目 | 当前 TWRP（16:28 Asia/Shanghai） | 先前 Android 基准 / UEFI configure |
| --- | --- | --- |
| `ro.build.version.release` | 17 | 17 / 170000 |
| `ro.build.version.security_patch` | **2099-12-31** | **2026-10-05** / 20261005 |
| `ro.vendor.build.security_patch` | **2099-12-31** | **2026-10-05** / 20261005 |
| `ro.bootimage.build.version.security_patch` | 空 | 空；不据此推断 TA boot patch 槽值 |
| KeyMint / keystore2 / qseecomd | 三个 init 服务均 running；listeners.registered=true | UEFI 独立实现；不运行这些 Android 程序 |
| recovery 全局绑定状态 | state2、空向量，两快照一致 | 既有 Android vold state2、空向量证据 |

当前属性只能证明采集时可见的值，不能直接证明 KeyMint 构造时采样值，也不证明
某个具体键的创建/绑定上下文。TWRP 的全局空 seed 证据不自动替换现有候选的固定
Android 绑定 pin，更不等于恢复/认证成功。

固定执行输入 SHA256：

- recovery `9aa603b1b2851df9c773c153f7df4520b7c634be0c15bc55f43c2fb83b82e4b0`
- keystore2 `c969b1d32054d05943a7a101eb0ea92c2063aec5d0cb2a555226197c5f4f5f4a`
- KeyMint service `104325882c4b03dde44daaf645b05272757fc3df0c69fb6e56fa0c2c27617dba`
- libqtikeymint `657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb`

四库完整 SHA、进程证据、捕获工具和辅助文件哈希均在证据 JSON；没有以 Android
runtime 的不同 libqtikeymint/libQSEEComAPI 版本替代 TWRP 当前映射的版本。

## keystore2 的 -62 分支

本轮固定 keystore2 的代码证据与局部合成执行补上了此前没有覆盖的中间层：

| 位置 | 已核验的事实 |
| --- | --- |
| recovery `0x250f28..0x250f50`、`0x251110..0x251134` | 构造 domain3/BLOB 与 namespace100 的描述符，随后经虚表调用 createOperation |
| keystore2 `0x1115a4..0x1115c8` | 检查返回结果/错误域，`cmn w8,#0x3e` 匹配 -62；不匹配转 `0x111648` |
| `0x1115fc..0x111630`、rodata `0x2a55a` | 匹配后的路径关联 `upgrade_keyblob_if_required_with: calling upgradeKey` 标签 |
| `0x112228..0x112244` | 经 vtable+0x48 调用中间层设备接口 |
| `0x113abc..0x113ae0` | 后续重用 `0x1249b0` 操作闭包 |
| `0x124ae4..0x124b18` | 闭包经 vtable+0x68 调用 begin 接口 |
| 固定 HAL `0x2f50c..0x2f574` | 非 legacy TEE upgrade 分支构造 0x2114，不是 0x2108 |

在私有模拟内存中仅执行九条实际状态判断指令：六组公开合成状态覆盖 -62、-33、
-64、0 和不同外层/错误域。仅 `(1,1,-62)` 到达升级分支入口；在入口即停止，
没有映射或执行任何 Binder、升级、分配器、密码学或设备调用。

上述指令、日志标签与
[AOSP 固定 revision 的 security_level.rs](https://android.googlesource.com/platform/system/security.git/+/d43c1b9db3510dd5c25d35a34b926389bfeb2d33/keystore2/src/security_level.rs)
中“KEY_REQUIRES_UPGRADE → upgradeKey → 重试操作”的流程相符。该源码仅作解释
对照，不宣称它就是此 stripped 二进制的精确构建源码，也没有捕获本机 metadata
密钥恢复实际进入升级分支的轨迹。不能由“TWRP 能解密”反推 UEFI 的原始 begin
本应直接成功，或反推可以把升级纳入当前只读恢复子集。

## 公开配置的离线差分

固定 TA 的 public configure 解析器分别接受以下两组输入并只在模拟 TA RAM 中
写入预期的三个字段；两组均返回0、configured=1，原始字节见审计 JSON：

- Android 基准：170000 / 20261005 / 20261005。
- 当前 TWRP 可见属性：170000 / 20991231 / 20991231。

这只证明请求的公开编码与局部解析成立；没有在手机上发第二组 configure，
没有把2099写进现有候选或改写旧证据，不能宣称它会解除真实 -62。
版本检查还包含 blob 格式、boot patch、vendor patch 及规范化后的 OS patch；
当前属性对照没有给出这些键内字段或实际 TA client 槽的完整值。

## 采集器修复、测试与失败记录

新增 `collect_fuxi_twrp_keymint_context.py`，只使用固定 getprop、pidof、stat/maps、
exe/库 SHA256 查询；只保存允许的映射文件名，不保存地址或整份 maps。17项模拟
测试覆盖身份、slot、服务未就绪、多PID、坏hash/maps、缺库、PID/属性竞态与参考
哈希不一致的显式报告。通过不代表真实捕获，真实捕获单独存档。

已有绑定采集器首次拒绝 `invalid binding object pointer`；另一次只读8字节指针
分类确认其非空、8字节对齐、带顶字节标签、去标签后在低48位范围内，未跟随指针。
此前仅 Android vold 处理此标签，TWRP recovery 没有。主机工具现对两者都只去除
顶字节，继续要求低48位、对齐与唯一私有可读写映射；不放宽其他地址位或读长。
新增 tagged TWRP 正例与非canonical指针反例后26项测试通过。随后完成固定指针8字节
与状态头28字节各两次的72字节捕获，state2/空向量稳定，未读取向量/seed内容。

另行尝试三个 `service check` 均退出127，未取得服务注册枚举证据；不把该失败当作
服务缺失或选择了 legacy/compat 路径。没有启动服务或安装工具。

本轮没有重启、flash、分区/slot写入或 KeyMint API 调用；TWRP 的挂载/解密行为不是
由本轮采集器触发。历史 SMMU FSR400、-33、真实密钥恢复、M3/M4/M5仍待验证。

## 后续实验边界

下一独立实机候选若要比较配置上下文，应以原始 begin 失败的 v3 路径为对照，
固定其余输入，仅改变经实机捕获的公开 patch 字段；不要在特性探针-33后继续
begin，不复用当前保留会话，也不加入 generate/upgrade/持久化。两组输出都必须
保留原错误与未知完成隔离，不能把一次成功或失败当作两个 -62 分支的唯一判别。
本轮交付是已绑定的上下文与离线证据包，尚没有这样的新启动镜像。
