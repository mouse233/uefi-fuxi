# M3 QTEE 共享内存桥闭环调用候选 — 2026-10-27

## 静态 ABI

对固定哈希 `qcom-scm.ko` 的反汇编给出标量 SMC64 形式：

```text
x0 = 0xC2000000 | (service << 8) | command
x1 = arginfo（低 4 位为参数个数）
x2..x7 = 参数
```

`__scm_smc_call` 用 `arginfo & 0xf` 判断参数个数，≥5 时进入额外参数缓冲路径；
本候选只实现标量路径。描述符头是 `svc 0x0c`，`enable 0x1c` 无参数、
`delete 0x1d` 一个参数（句柄）、`create 0x1e` 四个参数，owner 字段恒为 2。

`qtee_shmbridge_register` 的打包（probe 调用点 `w4 = flag^1`、`w5 = 6`）为：

```text
arg0 = phys | (per-VM 3-bit 权限)
arg1 = phys | 6
arg2 = size | (vm_count << 9) [| 0x1a，取决于模块内部状态]
arg3 = VMID 位（u16 数组，vm_count=0 时为 0）
```

`qcom_scm_create_shm_bridge` 把 SMC 返回的 a1 写入调用方句柄指针，a0 是状态。
模块在 create 成功后才登记本地节点，delete 时回传句柄；这些是静态事实，
不是已验证的 UEFI ABI。

## 候选行为

新增默认关闭 `FUXI_M3_SCM_BRIDGE_CALL`（要求 `FUXI_M3_SCM_INFO=1` 与驻留诊断）。
先做既有 INFO 自查询；仅当返回 available=1 时：

1. 分配一页 4 KiB（4 GiB 以下、页对齐）并写回无效缓存；
2. `enable`（0 参数）；
3. `create`（`vm_count=0`，`arg0=phys`、`arg1=phys|6`、`arg2=4096`、`arg3=0`）；
4. 取 a1 为句柄，`delete`（1 参数）；
5. 仅在 delete 尝试之后释放该页。

每一步先打印 begin 再发起同步 SMC，返回后打印 a0..a3；enable 或 create 失败
即停止，不继续下一步。全程无密钥、无 TA、无 UFS 命令、无解密。

`tools/test_fuxi_m3_bridge_call.py` 用 ASan/UBSan 验证 FNID、arginfo、四个参数
的打包、VM 计数位移、对齐/大小/上限拒绝与 a0/a1 解码；不执行 SMC。

## 候选与检查

`out/m3-bridge-call-v1`：镜像 SHA256
`e711317c585a20cf66bd97ec119972bacafe4db54a823297b7c1342115f0dd28`。
13 项交付检查退出 0；交付 EFI 有 1 条 `smc #`（`ArmCallSmc` 实现），两种对照
模块均为 0；交付 EFI 含 `FUXIM3 BRIDGE` 全部标记。

## 未验证边界

- 同步 SMC 没有硬超时：每次调用都可能停在 begin 行，需要现场保留画面并手动重启。
- EFI 引导服务内存是否被 QTEE 接受为桥内存未知；模块注册的是 DT 预留 carveout。
- `arg1` 重复物理地址、`arg3` 的 VMID 语义、条件 0x1a 标志均为静态推断；
  实机返回码和句柄是第一次真实证据。
- 即使 create 成功，也只证明该页被登记；不证明共享内存可被 TA 访问、
  不证明 KeyMint 会话、不证明装钥或解密。

## 2026-10-28 追加：内存池与参数解释更正

固定模块的该probe分支通过__get_free_pages分配默认4MiB普通页，DMA映射后建立gen_pool；
上文“模块注册的是DT预留carveout”的笼统说法不适用于此分支。
调用类型和返回槽位已由标准桥专题更正；HLOS/VM/权限分支新证据见fuxi-m3-bridge-hlos-20261028.md。
历史原始记录保留，不将任一静态分支视为部署固件等价或C2成功证明。
