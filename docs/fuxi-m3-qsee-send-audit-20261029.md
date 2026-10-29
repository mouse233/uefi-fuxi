# setVersion 请求对象封装与 TA 状态指令：离线复核（2026-10-29）

## 固定的用户态封装

从 SHA256 `68f3829ba4b7faaf8b873fd0dce7dabd03b2bdd750debbae56b1dbe326f87da5`
的 A16 TWRP 恢复 `libQSEEComAPI.so`，SHA256
`5c996c509fdab3e5925af52f59d554bf54a7c54743c668017a83ef0d1b4e65ed`。
这是一份 A16 输入；本轮未独立取得 A17 的该文件，不能推定 A17 字节一致。

`tools/audit_fuxi_m3_qsee_send.py` 在隔离 Unicorn 中执行固定库的
`QSEECom_send_cmd`，以合成请求 `21 31 00 00 a1 0b 18 c8` 和空响应区为输入，
只在远端 object invoke 边界截获参数并模拟返回成功；没有执行 TA 或访问设备。
ELF class 2 观察到 op0/counts 0x424、请求8字节、响应容量0x9ff8、is64=1、
四个空输入对象；输出请求和响应指针分别与输入别名。class 1 对照 is64=0。
公开固定内核参考使用独立区间编排 BI/BO 并在完成时复制 BO：这解释了对象参数
别名与线格式中不同偏移不矛盾；独立模型构造的六个描述符与候选源码一致。
这验证厂商用户态函数的本地模拟，不证明设备内核、缓存或安全世界收到相同消息。

空对象必须区分层次：厂商接口中的 Object_NULL 是 null invoke/context；公开内核
参考把用户空间 null 句柄 -1 转成 TZ null 0。当前候选的 OI 描述符为 0，与该固定
参考一致；仍不证明设备固件全部实现一致。

## 实际 keymaster_a 镜像中的状态线索

只读分区大小 524288、固定 SHA256 `2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6`。
`tools/audit_fuxi_m3_ta_status_sites.py` 对 ELF64 可执行段按 4 字节扫描 `MOVN Wd,#39`
（产生 32 位 -40）的特定指令编码，共找到 16 处；详细偏移在本机报告
`out/m3-setversion-macos-20261029/ta-status-sites.json`。可执行段可含数据，也存在
其他构造 -40 的方式；这些位置未证明被执行、未关联到 setVersion 响应，不能据此
确定错误源或语义。此结果说明单凭出现 -40 指令不能定位对应分支。

检查报告 `qsee-send-audit.json`、`ta-status-sites.json` 分别保存于本机候选目录。
这轮不更改 UEFI 或设备，不跳过失败保护。下一步是追踪实际 TA 命令分派及调用上下文，
并核实厂商驱动和固件的差异；仍需证据才能选择安全的修复方案。
