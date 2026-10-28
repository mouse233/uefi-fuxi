# M3 TA / QSEEComCompat 后续契约深审 — 2026-10-28

本轮止于离线审计和语义模型，没有接入生产 UEFI，没有执行设备、SMC、厂商代码或 TA。
HLOS 桥创建/删除/释放已实机通过；root/client-env、UID122 loader 和 TA 仍无本轮实机成功证据。
独立工具 audit_fuxi_m3_ta_contract.py / test_fuxi_m3_ta_contract.py 的报告与汇编位于
out/m3-static-advance-v1/ta/。不修改他人未提交的 A17 交叉分析稿。

## 固定本地二进制与公开参考的分层

工具固定 smcinvoke_dlkm.ko（831a6db7…9348）、libqtikeymint.so（657093d0…ddcb）、
libkeymasterdeviceutils.so（1c2172c4…d7d2）的完整 SHA256。
公开参考是既有固定提交 9e8972287159837a256d0afcddc3f636f67ce8dd 的五个文件，
逐文件 SHA256 验证；并非证明其与本机 ko 为同一构建。
八个输入分别单字节篡改均被拒绝。具体哈希、反汇编范围和输出哈希均保存于 audit.json/tests.json。

| 固定本机 ko 位置 | 静态事实 | 后续门槛 |
|---|---|---|
| 1e3c..1e8c | get_client_env_object 后，open UID122，op0/count1001 | UID122 是 loader 对象，不是 KeyMint TA UID；必须检查返回非空远端对象 |
| 1f40..1f80 | lookupTA op2/count1001，失败后才 firmware_request_from_smcinvoke | lookup 可能返回已有 app，但名称、授权、远端生命周期仍需实机 |
| 1fb8..1fe4 | loadFromBuffer op1/count1012，distName BO容量64 | 两个BI、一个BO、一个OO，没有OI/local对象输入 |
| 1c84..1cf0 | app_arch==2构造is64，sendRequest op0/count0424 | BI4/BO2/OI4/OO0；参考中四个OI均为空、embedded offsets为空 |
| 74c8..77fc | b00 ELF class、e_phnum/e_phoff，request split、allocate shm、memcpy | 签名、版本和可用固件输入仍不由这些调用证明 |

公开参考的 load_app 先 lookup，再走 loadFromBuffer；不能把它与 loadFromRegion 混淆。
loadFromRegion 是 BI1/OI1/OO1，输入 ELF region 对象通常要求更多内存对象管理；
本机已核对路径采用 loadFromBuffer，不以该方法为本轮实现目标。
无OI或四个null OI并不等于 transport 永远不需要 callback。inbound request、listener、
piggyback、部分输出和中断状态仍可能出现；没有运行证据前继续隔离资源、停止后续调用。
不能为推进静态实现而假定所有 TA 调用都无回调。

另一个架构边界：本机lookup成功分支@1f70直接跳到@2028，绕过@2000读取ELF EI_CLASS、
@2018保存context+0x30的步骤；sendRequest@1c84只读取context字段并与2比较。
因此lookup复用已有TA并不为未来UEFI证明is64；不能仅按keymaster64名称推断该位。
参考上下文由kzalloc分配，但本专题不将参考初始化与部署ABI视为完整等价。

## 40KiB 用户态缓冲不等于 SMCI 输入页大小

参考封送把每个BI和BO分别放入 in_msg，并按8字节对齐。独立模型例子：
request=8B，response capacity=40952B，二者合计40960B（0xa000）；
is64=4B，embedded offsets=0B，四个输入对象均为null。

| 内容 | offset | bytes | 说明 |
|---|---:|---:|---|
| 头+10个8B描述符 | 0 | 92 | 12+10×8，payload起点对齐至96 |
| BI request | 96 | 8 | |
| BI response初值 | 104 | 40952 | |
| BI embedded offsets | 41056 | 0 | |
| BI is64 | 41056 | 4 | 后续对齐至41064 |
| BO request | 41064 | 8 | 独立保留输出空间 |
| BO response | 41072 | 40952 | |
| 消息末尾 | 82024 | — | 页对齐后86016B（21页） |

该模型不包含独立的 callback out_msg；也没有执行 vendor 编码器证明逐字节等价。
它足以否定“把8KiB C2桥直接当完整KeyMint send缓冲”的推广。
最大16MiB模型上限仅为离线资源限制，不是手机或固件可接受上限。

## 固件输入与边界模型

固定参考 firmware_request_from_smcinvoke 从 name.b00 读取ELF/program table，再读 b01..bNN，
按 p_offset 拼接为内存映像；不是把一个 .mdt 文件当作可直接加载的完整 TA。
本地已展开 ramdisk 全树未发现 keymaster64.bXX 或 keymaster.bXX。
用户态路径 /vendor/firmware_mnt/image 是运行环境的输入线索，不能视作本机已恢复相同固件。
不下载或猜补版本。已有TA、版本匹配、签名/metadata/证书和调用者权限都仍需独立证据。

新增纯主机 ELF64 分片规划器只对合成输入测试：header/table范围、class/endian、
phnum≤100、缺失/额外分片、文件大小、memsz、重叠和总长拒绝。
这些是比参考代码更严格的保守接受子集，并不认证TA、不声称支持所有合法厂商分片。
lookup/load/send 布局模型、无效句柄/文件名/容量与响应status/长度测试共46个向量通过，
其中包含八个固定输入篡改拒绝。它们不是生产UEFI测试，也不是TA执行验证。

## KeyMint 初始化顺序与版本语义

本工具复用重跑既有固定KeyMint审计：用户态优先 keymaster64，失败回退keymaster，buffer0xa000；
加载后先命令0x200取版本；非legacy配置分支先0x3121/serializeInteger(200)，
再0x2116/serializeClientParams；convert另为0x311d。
整数200不能写成Android release16/17。OS属性解析、OS version/patch编码和TA实际接受的
configure参数仍是另一个待核验问题，不能由该版本协商常量推得。
TA命令status/长度与SMC a0、对象result分层；保守响应模型要求status零、头≥8、
声明长度同时落在实际字节和capacity内，不把convert输出当裸AES key。

## 必须上机的位置

当前最先需要运行证据的是HLOS桥上的C2 root register/release。没有实际client-env句柄，
离线构造更多后续消息无法证明授权或跨调用状态，不能跨过去接TA执行。
C2通过后，可独立准备小缓冲的loader open(UID122)→release验收；
再独立验证lookup的对象与清理，而不是立即加载TA或convert。
lookup不满足时需恢复同版本TA分片并验证metadata/签名及尺寸，
然后才能把已建模的loadFromBuffer/callback/资源生命周期设计成受限候选。
send/getVersion、协议200/configure参数与KeyMint密钥转换均是再后面的不同验收点。
