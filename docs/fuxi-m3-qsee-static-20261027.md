# M3 QSEE / smcinvoke 静态核对（2026-10-27）

## 范围与结果

输入是用户提供的 TWRP-FUXI-A17.img 中已展开的 ramdisk，镜像 SHA256
`56f5f36e9aaeb9e79815c702d9e9196c8c0e1b03d363ec4e4c9646cd4af1444c`。
没有在设备上调用 QSEE/KeyMint，没有读取或保存 key/blob，没有执行厂商模块。
实机已有 INFO 可用性结果不能证明这些接口或密钥在 UEFI 可用。

`tools/audit_fuxi_m3_qsee.py` 绑定具体文件 SHA256，检查 ELF 符号种类、
模块依赖和 AArch64 注册调用；结果见 `out/m3-qsee-static-v1/audit.json`。
被修改的 `smcinvoke_dlkm.ko` 拒绝测试通过。此工具只验证它列出的固定静态
事实，不声称执行流、接口 ABI、内核版本兼容或 QTEE 授权已在设备得到验证。

## 本设备镜像的直接证据

- `libqtikeymint.so` 导入 `keymasterutils::KeymasterUtils::qseecom_dev_init`
  和 `sendCmd`；这两个实现由 `libkeymasterdeviceutils.so` 导出，后者导入
  `QSEECom_start_app`、`QSEECom_send_cmd` 和 `QSEECom_shutdown_app`。
  有这些导入/导出不等于确认运行时每次都走该路径或恢复环境的调用成功。
- `smcinvoke_dlkm.ko` 的 `get_qseecom_kernel_fun_ops` @0x1ba4 将
  `qseecom_driver_ops` 传给 `provide_qseecom_kernel_fun_ops`；该注册入口
  由 `qseecom_proxy.ko` 实现。前者含 `__qseecom_start_app`、
  `__qseecom_send_command`，并导入 `qcom_scm_invoke_smc`、
  `qcom_scm_invoke_smc_legacy`、`qcom_scm_invoke_callback_response` 与
  qtee_shmbridge 接口。模块依赖清单也列出 proxy、SCM 和其他驱动。
- 因此 `qseecom_proxy.ko` 只是代理；不能把它当作完整的 UEFI 可调用 QSEE
  实现。`libqtikeymint` 还依赖 Android Binder、运行库和 HAL，不能仅搬运 ELF
  到 UEFI 便获得 TEE 会话。

与 [公开 Qualcomm smcinvoke 实现](https://android.googlesource.com/kernel/msm-modules/securemsm/+/refs/heads/android-msm-eos-5.15-tm-wear-kr3-dr-eos/smcinvoke/smcinvoke_kernel.c)
相比较，该版本通过 client environment、兼容 app loader 和对象调用建立会话，
并通过共享内存传输。这是另一设备/分支的源码，仅为设计线索，不能当作本机
二进制的完全匹配源码或 UEFI ABI。是否存在同一固件版本的源码尚待核实。

## 下一步工程门槛

先把 fuxi 实际 `smcinvoke` 请求/响应、对象与回调、共享内存地址/生命周期、
错误和中断语义与匹配源码逐项对照；确认 KeyMint TA 选择与版本绑定、调用者
权限，以及 UEFI 阶段共享内存桥是否存在。完成前不加载 TA、不使用随机命令、
不操作密钥或 ICE keyslot。再设计有界只读验证，其失败必须停止并保留诊断。
现有 M2 clean checkpoint 和只读策略继续生效；当前尚无设备端解密。

复现：`python3 tools/audit_fuxi_m3_qsee.py --ramdisk out/twrp-a17-analysis/ramdisk
--output out/m3-qsee-static-v1/audit.json`；篡改拒绝测试为
`python3 tools/test_fuxi_m3_qsee.py --ramdisk out/twrp-a17-analysis/ramdisk`。

## 固定提交的 SM8550 候选源码

发现 [LineageOS SM8550 模块源码的 smcinvoke 目录](https://github.com/LineageOS/android_kernel_xiaomi_sm8550-modules/tree/9e8972287159837a256d0afcddc3f636f67ce8dd/qcom/opensource/securemsm-kernel/smcinvoke)，
固定提交 `9e8972287159837a256d0afcddc3f636f67ce8dd`；下载七个文件及
SHA256 见 `docs/evidence/fuxi-sm8550-smcinvoke-source-20261027.json`，本地只读
副本在候选 out 目录。该源码针对 SM8550，但尚无证据证明它与 TWRP 的 `.ko`
是同一次构建或 ABI 完全一致。

该候选源码含与实机模块对应的 `get_qseecom_kernel_fun_ops`、
`__qseecom_start_app`、`__qseecom_send_command` 和 loader UID 122；模块中
已独立确认注册调用和这些符号。源码描述 root/client environment、app loader、
共享内存、invoke 和 callback 响应路径；`smcinvoke.c` 列出 invoke/callback
命令号。此类常量只是后续逐项匹配的线索，尚未验证本机固件支持或允许调用。
不可根据同名符号直接发起 TA 请求，须先比对请求布局、长度、物理地址、
共享内存桥、返回/回调及资源生命周期。
