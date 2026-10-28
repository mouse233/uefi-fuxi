# M3 root → loader 组合诊断（C2/C3 批处理）— 2026-10-28

## 触发与方案

用户询问能否一次开机验证多项内容，并选择“一次构建覆盖一组相关验证，一次开机按结果逐级推进，
遇到无法解释的状态才停止”。本批因此把已验证的 HLOS 桥、最小 C2 root register/release 与
loader open/release 编进同一镜像，一次启动即可覆盖到对象释放与桥清理。

## 新增固定证据（loader 契约）

新增 tools/audit_fuxi_m3_loader_contract.py，固定两份本地 ELF 与四份公开参考输入；
六项逐一篡改均被拒绝，原始反汇编保存在 static-loader-contract/open-loader.asm。

- smcinvoke_dlkm.ko .text @1e38..1e94：get_client_env_object 成功后把 0x7a(122) 存入栈，
  随后 w1=wzr、w3=0x1001 经对象调用入口发起 open。
- IClientEnv.h：IClientEnv_open 以 ObjectCounts_pack(1,0,0,1) 调用 IClientEnv_OP_open(=0)，
  BI 为 uid 的 uint32，返回对象写入 a[1]。
- smcinvoke.c：线格式末端 = 头 + 每对象参数 × counts；BI 偏移按 8 对齐。
- 参考类型声明直接抽取编译并静态断言：线格式 28 字节、OO 在 +20、BI 偏移对齐后 32。

因此本批 open 消息为：12 字节头（handle/op0/counts1001）、+12 的 BI 描述符（offset32/size4）、
+20 的 OO 描述符、+32 的 UID 122；输入输出各 4096 字节，仍是同一 8 KiB 连续页。

以上是固定模块与固定参考的自洽性检查，不是本次部署固件的等价证明，也不证明 lookup 或权限。

## 执行顺序与停止点

`plan=root/open122/release-loader/release-env/delete`

1. 桥 enable（42000c1c）→ 2. 桥 create（HLOS：1 VM、VMID3、权限6）→
3. root register（op5/counts1100）→ 4. open UID122（op0/counts1001）→
5. release loader（opFFFF/counts0）→ 6. release environment → 7. delete 桥。

每一步完整打印实参与 a0..a3，并单独校验缓冲区布局；只有前一步取得本探针接受子集内的明确终态，
才进入下一步。任一步返回未知/错误，日志停在 `BATCH stop=<stage> passed=<mask>`；
已创建的桥句柄、对象句柄与 8 KiB 页保持原样，不继续调用、不擦写、不 free、不重试。
`passed` 位依次代表 root、loader open、loader release、environment release、delete 完成。

## 边界

- 只 open/release UID122；不发送任何加载请求、TA 标识、KeyMint 消息或密钥操作。
- 8 KiB 仍不足以承载 TA 通道：此前封送模型典型请求为 86,016 字节（21 页）另加 callback 输出区。
- 不读取 blob/key、不转换、不写 ICE、不解密、无分区写入、无回调执行、无重试。
- 同步 SMC 无硬超时；合法 callback/piggyback 会落到未知态并停止，不据此判定固件 ABI 错误。
- 一次开机只允许一次 fastboot boot；未知态不自动重传，需重新取证。

## 验证

- 18 项完整交付检查全部退出 0（含镜像、SMMU、路由、M2 与既有 M3 回归）。
- 78 个批处理生产生命周期向量（ASan/UBSan，模拟 monitor）：分配失败、桥 enable/create 失败、
  root 未知返回、loader 未知返回、两个 release 的失败与顺序、缓冲区各偏移篡改、64 位句柄、
  同一句柄被两个所有权引用等路径均验证“就地停止并保留页面”。
- 148 个仅 C2 向量（loader 编译关闭）与 24 个桥向量回归通过，确认默认路径未受影响。
- 报表行数上限由 128 提到 192；批处理测试在 128 行基线后仍断言无丢弃、无截断。
- 56 个交付源码绑定与镜像 SHA256 一致。

## 下一决定性观测

一次实机启动需回答：桥 create 是否仍成功、root register 的原始返回与 OO、loader open 的返回与句柄、
两个 release 的终态、delete 与 released/PARK。出现未知态即停在对应 `stop=`，不继续后续阶段。

## attempt-01 实机结论：停在 root-register

照片IMG_7176..JPG，SHA256 b56e533fbdd4172ec896b39dfa9e50d9ba73e32fa8d272c7a0daff95457a35eb。本批在root-register阶段按设计停止，loader未尝试。

- 桥：page phys=C6A3D000（8KiB）；enable x0=42000C1C返回a0..a3=0；
  create x0=42000C1E，参数C6A3D006/C6A3D006/2200/3，返回a0=0、a1=0、a2=2EC81021、a3=0。
  显式HLOS配置再次被接受，桥句柄2EC81021。
- root register：x0=72000602、x1=224、handle=1、op=5、counts=1100，in=C6A3D000、out=C6A3E000。
  原始返回a0=a1=a2=a3=0；缓冲区回读hdr=1/5/1100、oi=0/0、oo=2/0，
  输出页首两字为00010002/0000FFFD，其余打印字为0。
- 判定：探针要求输出页全零且单一OO描述符可解析，因此返回EFI_COMPROMISED_DATA，
  BATCH stop=root-register passed=0 retained=1；未做句柄判断，未open loader，
  保留桥句柄与8KiB页，未擦写、未free、未重试。a0..a3全零只通过传输元组检查，不等于对象成功。
- OO回读为offset=2/size=0不是可用对象描述符；00010002/0000FFFD的含义尚未归类，
  本轮不把FFFD写成错误码，也不据此判固件ABI错误。
- UFS stop=1、db=tdb=run=0、hcs=0000010F、is=0、poisoned=0、ready=0；
  SMMU GFSR=0、FSR=00000400、far=1BBAE7DF98DF仍残留，不宣称完整路由恢复。
  M2的10527字节与SHA256 14f3d867…0991仍一致；PARK与cached report end可见。
- 镜像12b094bf368046687ee6b9851ff843758d5c3069f8c58420f5fcdb0af8a99c91与提交a4e0fc5023c9f0316cf1b54675ba9f305b286ffd的56个源码绑定、18项检查、78/148/24向量仍有效。
  无TA加载、无密钥使用、无转换、无解密；C2未通过，C3未开始。
- 下一步是离线把输出页布局与object-cmd2的返回分层对上，再决定是否放宽/改写接受子集；
  在此之前不重复上机。
