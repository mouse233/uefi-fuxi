# M3 SMCI 响应解码：root register 的 out 页与对象句柄 — 2026-10-28

## 触发

`m3-smci-loader-hlos-v2` 的 attempt-01 在 root register 停止：
原始返回 `a0=a1=a2=a3=0`，请求页回读 `hdr=1/5/1100`、`oi=0/0`、`oo=2/0`，
out 页首四字 `00010002/0000FFFD/0/0`，探针返回 `EFI_COMPROMISED_DATA` 并保留页面。
本文件把该观测与固定参考逐项对齐，判断哪一层是探针自己的规则。

## 固定参考的语义

1. `prepare_send_scm_msg` 只在传输成功、`response_type` 非 inbound 且 `result` 为零时
   调用 `marshal_out_invoke_req` 取回输出对象；`result` 非零时不做该步。
2. `is_inbound_req` 只认 `SMCINVOKE_RESULT_INBOUND_REQ_NEEDED=3`、
   `QSEOS_RESULT_INCOMPLETE`、`QSEOS_RESULT_BLOCKED_ON_LISTENER`。**0 不是 inbound。**
3. 既有审计已固定返回分层：`a0` 为 SCM 返回，`a1` 为 response_type，
   `a2` 为对象 result，`a3` 为 data（见 fuxi-m3-root-contract-20261028.md）。
4. `union smcinvoke_tz_args` 在 OO 方向是 **32 位 `int32_t handle`**，不是 buffer 描述符。
   `marshal_out_invoke_req` 从 `in_buf + 12 + 8*(BI+BO+OI)` 读取；本请求 `counts=0x1100`，
   所以位置是 **+20**，后 4 字节不参与。
5. `TZHANDLE_IS_LOCAL(h)` 看 bit31；远端对象 bit31 为 0。句柄 2 不是本地对象，
   也不等于本探针拒绝的 0/1。
6. invoke 路径在复制结果后**无条件**调用 `process_piggyback_data(out_msg)`；
   其结构为 `{version, op, counts, objs[]}`，循环次数在 **+8**，`counts=0` 时不执行任何对象操作。
   若按 `struct smcinvoke_tzcb_req` 读，`counts` 在 +12，同样为 0。
7. 参考实现从不要求 out 页全零；它只在 inbound/piggyback 语义下消费该页。

## 与本机观测的对应

| 观测 | 固定参考下的含义 |
|---|---|
| `a0=0` | SCM 传输成功 |
| `a1=0` | response_type 0，不是 inbound（3） |
| `a2=0` | 对象 result `OBJECT_OK` |
| `a3=0` | data 0 |
| `oo=2` | 32 位远端对象句柄 2（bit31=0） |
| `out=00010002/0000FFFD/0/0` | 前两字可为 version/op；`counts`(+8) 与 +12 均为 0，两种读法都没有待处理对象 |

因此 v2 的 `EFI_COMPROMISED_DATA` 来自探针自己的“out 页必须全零”规则，
不是观测到的 ABI 冲突。该规则此前被明确记录为有限探针的保守子集，而不是 ABI 要求。

## 仍未证明

- 句柄 2 是否真是 client-env 对象、是否具备调用者权限；参考要靠
  `get_uhandle_from_tzhandle` 才能判定，本探针没有这一层。
- `0x00010002` / `0x0000FFFD` 的语义不在固定输入内：不解释、不写成错误码。
- 固定参考与部署固件的等价性仍未证明；上述分层来自既有固定模块指令审计与固定参考。
- raw 全零只表示该分层下的成功元组，仍需 release 与后续阶段的实机返回才能判 C2。

## v3 的规则变更

- out 页前 8 字节允许非零（version/op），要求 **+8 到页尾全零**；
  对象仍只取请求页 +20 的 32 位句柄，其余任何不一致继续 `EFI_COMPROMISED_DATA`。
- 新增 `nz=`（out 页非零字节数）便于下一次判读。
- 测试同步：82 个批处理向量在每次对象调用都模拟 version/op 且 counts=0；
  148 个仅 C2 向量同样模拟，并把 out 尾字节 (+4108/+8191) 作为拒绝向量。
  这一改动**放宽了探针自己的接受子集**，不是放宽对固件返回的验证：counts 非零、
  尾字节非零、句柄非远端或头部回显不符仍全部拒绝并保留页面。

## 下一次上机

预期：register 接受远端句柄 2 → open UID122 → release loader → release env → delete。
是否真的走到哪一步仍只以 `BATCH stop=` 与照片为准；release 未知时保留页面、不重试。
