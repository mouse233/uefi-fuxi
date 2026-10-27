# M3 SMCI 响应和资源生命周期：主机设计实验

固定 SM8550 候选源码 `smcinvoke.c` 的 `prepare_send_scm_msg` 在传输成功、
无待处理 inbound 请求且对象 result 为零时，调用 `marshal_out_invoke_req`
读取 **in_msg** 中的输出对象；`out_msg` 可能包含 callback 或 piggyback
对象释放，另行处理。两块 buffer 均通过 qtee_shmbridge 分配；legacy 路径
显式 flush/invalidate。远端对象释放编码为 handle、`0xffff`、counts=0。
这些仅为候选源码事实，不代表设备 ABI 已得到完整确认。源码的 listener、
callback、引用计数、共享内存桥与释放失败路径不能省略。

`tools/m3_smcinvoke_response.py` 只验证两种已知合成请求的单个输出对象、
固定 buffer 长度、头部和输入描述符、remote handle 以及空 out buffer；
任何非空 out buffer、未验证的终态、错误或异常均返回 Quarantine，要求
保留资源并停止后续操作。调用者必须从未来已验证的 transport 给出终态，
本草案不解析寄存器或证明 cleanup 安全。合成 release 仅为字节布局实验，
不是可调用的对象管理器。真实 QTEE 必须正确处理 callback、piggyback、
已交出的对象以及失败恢复，不能把整个空 out buffer 作为实际 ABI 要求。

`tools/test_m3_smcinvoke_response.py` 测试成功响应与固定 release 编码、
出错/未知终态、损坏描述符、null/local 输出、piggyback、长度与未知请求。
未执行 SMC、未接触设备或密钥。仍需将更多候选源码的 QTEE transport 和
共享内存桥与固定哈希设备模块核对，再构建可回收的有限会话候选。

固定哈希 TWRP `smcinvoke_dlkm.ko`（SHA256
`831a6db7570e66729db84cd0a7ddc63f8cdbc4b03fd250dee15b80b561969348`）
的反汇编局部对照：`smcinvoke_release_tz_object` @0x7c6c 装载 0xffff，
@0x7c80/0x7c88 使用 4096 字节，@0x7c84/0x7c8c 写句柄及操作；
`invoke_cmd_handler` @0xc520/0xc528 调用 flush，@0xc548 调用 legacy
SMC，@0xc554/0xc5d8 调用 invalidate；@0xc5bc 为 callback response，
@0xc5fc 为另一 invoke 调用。静态局部一致不证明所有分支及 ABI 等价。
