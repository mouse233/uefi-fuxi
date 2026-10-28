# M3 root/SMCI 对象契约深审 — 2026-10-28

## 已固定的事实

新增 tools/audit_fuxi_m3_root_contract.py，固定两份本地 ELF 模块和四份已固定公开参考输入；
六个输入分别修改一字节均被拒绝。审计不执行厂商代码、SMC 或手机命令。
完整原始片段和 root-contract-tests.json 位于 out/m3-static-advance-v1/root/。

本地 smcinvoke_dlkm.ko 的 get_client_env_object @18a8/@18ac 是 op5/counts1100，
@18c0/@18c4 清零两个 Object 参数。固定参考 smcinvoke_kernel.c 明确以 Object_NULL
调用 registerWithCredentials；IClientEnv.h 的接口是 0 BI/0 BO/1 OI/1 OO。
参考类型声明经临时 C 编译静态断言：头12字节、描述符8字节，OI在+12、OO在+20，
两个描述符末尾+28。参考 marshal_out_invoke_req 从 in_buf 而不是 out_buf 取 OO。
固定二进制 marshal_out @c748/@c74c 亦使用描述符乘8、头加12的布局。

qcom_scm_invoke_smc @7270 的 cmd2/owner0x32/arginfo224/type2 与生产72000602相符。
@731c/@7328/@7334 依次把 res[1]/res[0]/res[2] 送给对象result/response_type/data，
结合底层res=a1..a3，分层是 raw a0 SCM、a1 response、low32(a2) object result、low32(a3) data。
root和invoke没有共用桥create的a1服务结果/a2句柄语义，不能混用两种解码。
远端对象release是opFFFF/counts0，输入输出各4096字节，证据在固定模块@7c6c等。

## 生产代码的严格子集与静态限制

目前 all-zero a0..a3、输入头/保留字节不变、空out页、OO>1且非local位，都是有限探针的
保守接受策略，不是完整QTEE ABI要求。参考驱动允许callback/listener/inbound请求及piggyback；
遇到它们保留页并停止是正确的阶段边界，不能据此报告固件ABI错误。
非零a0时绝不能把a1/a2零当对象调用成功；对象返回错误也不是SCM传输错误。
返回handle1在抽象remote定义中不因数值1成为local，但本探针拒绝root别名是保守限制。
非空padding/tail也可能只是未建模行为，不应盲目放宽校验。

固定invoke_cmd_handler二进制和参考源码显示legacy明确sync输入输出缓存；cmd2分支没有相同的
显式调用。UEFI的clean/invalidate序列并不因此获得与Linux DMA/pool或安全世界相同的保证。
已通过的HLOS桥创建删除，证明页面注册闭环，不证明安全对象已消费两页或信任调用者。
零VM阶段的FFFFFFFF80000001仍不能由此审计归类，也不能归因权限/缓存/root op。

## 必须上机的边界

本轮没有发现要求重写当前null/op/counts/OO偏移或72000602参数的静态矛盾。
可继续构建HLOS桥上的最小root register/release候选，但下一步有决定性的未知量只能实机取得：
实际raw返回、是否有可接受的remote OO、是否触发callback/piggyback，以及release/delete终态。
成功之前不能推进TA会话；未知状态不resume、不重试、不擦写、delete或free未确认所有权的页面。
即便该有限闭环通过，也只证明本次root/release，不证明通用对象管理器、TA、密钥转换或解密。

## 2026-10-28 追加：C2/C3 组合批处理

新增默认关闭的 --m3-smci-loader/FUXI_M3_SMCI_LOADER，仅在 HLOS object 模式下与本文件所述 root 探针串联：
root register 成功后才 open UID122，再依次 release loader、release environment、delete 桥。
loader 消息与固定模块指令模式的绑定见 fuxi-m3-smci-loader-20261028.md；本文件对 callback、
缓存与所有权边界的结论同样适用于该批处理，未知态不继续、不重试、不释放未确认所有权的页面。
