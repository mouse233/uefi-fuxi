# M3 smcinvoke SCM 可用性候选（2026-10-27）

固定 SM8550 候选源码与 A17 的 qcom-scm.ko 反汇编分别显示 owner 0x32、
service 0x06 的 legacy invoke、callback response、object invoke 命令 0、1、2。
设备二进制中的 `qcom_scm_invoke_smc_legacy`、`qcom_scm_invoke_smc`、
`qcom_scm_invoke_callback_response` 生成的 descriptor 可复查于对应反汇编。
公开源码是候选版本，并非已经确认与本机二进制构建一致。

本候选仅通过已实机成功的 SMC64 INFO/IS_CALL_AVAILABLE 查询 subject
`0x32000600`、`0x32000601`、`0x32000602`。先自查询，失败/不可用不进入
subject 查询；每项异常则停止后续查询。白名单只允许明确列出的 ID，实际
调用的 x0 恒为 INFO，不直接执行 subject；不建立 QTEE 对象、处理共享内存、
读取密钥或加载 TA。主机 82 组数据/参数测试经 ASan/UBSan 通过。

同步 SMC 没有软件硬超时；最多四次调用中任意一次可能不返回。开始日志能
定位进度，但无返回不代表 unavailable。可用性不证明对象接口、共享内存、
权限或解密可用。未上机；候选和结果见 `out/m3-smcinvoke-avail-v1/REVIEW.md`。
