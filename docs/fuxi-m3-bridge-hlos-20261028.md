# M3 显式 HLOS 桥参数对照 — 2026-10-28

## 触发与证据

标准零VM候选create返回a0=0/a1=5C/a2=0，没有取得按固定ABI可接受的句柄。
本轮不猜5C含义，而核对固定qcom-scm.ko的probe/register完整分支：

- @96f0..9708：栈中VMID=3、权限=6；@970c查找.rodata+a91的qcom,support-hypervisor。
- @9714..9730：记录属性存在与否，非hypervisor分支选择VMID3数组。
- @99ac..99cc：ns_vmids来自所选数组，vm_count=flag^1，tz_perm=6；未声明属性时count=1。
- @9194..91b4：每VM权限压3位、VMID压16位；@91d4..91fc与物理地址/大小组合，并只在hypervisor分支加入0x1a。

仓库fuxi.dtb的桥节点只有compatible，无support-hypervisor，SHA固定见evidence JSON。
此前固定平台kalama.dtsi亦如此。它们不是手机当前部署DT/overlay的证明。
公开Qualcomm驱动的qtee_shmbridge_init/register代码与此分支含义一致；
已保存原文并校验Git blob 26fc6114172686534dba0d564a4c01de5b31a0d2，非精确设备版本证明。

## 参数与边界

新增默认关闭--m3-bridge-hlos/FUXI_M3_BRIDGE_HLOS，限定桥诊断，禁止与root/blob/key/context组合。
对于独立低4GiB的8KiB连续页，标准create四参：
arg0=phys|6；arg1=phys|6；arg2=0x2200；arg3=3。
它们组成一个相互依赖的HLOS注册配置，不是“只改一个bit”的实验。
仍使用42000c1c/1e/1d，enable a0=a1=0；create仅接受a0=a1=0且a2非零64位句柄；
delete只消费a0，按固定包装。无fallback/retry、对象、TA、blob、密钥、解密或分区写入。
创建未知或删除失败时保留页且不再擦写/free。

本机模块默认池在@9754..97a8分配4MiB普通页，再DMA映射并建立gen_pool；
因此早期文档笼统称“模块注册的是DT预留carveout”不符合该固定分支，现追加更正。
本候选仅8KiB有界桥对照，未复现Linux完整DMA设备、池管理、VM运行态或安全世界缓存契约。
未切换hypervisor，不加入无证据的0x1a；不能由静态证据宣称固件必然要求HLOS配置。

## 验证

标量参数及无效输入测试；零VM/HLOS两配置各12个生产生命周期向量，共24个ASan/UBSan向量。
固定模块probe/权限/普通页池/DTB审计与篡改拒绝；既有C2双模式56向量、C1 F2FS/SHA、INFO五向量回归通过。
15项完整交付检查退出0，56个交付源码绑定。硬件pending，C2仍未通过。
