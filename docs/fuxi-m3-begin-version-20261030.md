# M3 begin 版本校验直接路径与当前公开字段（2026-10-30）

本轮闭合了 begin 到版本校验的直接调用链，并从当前 TWRP 只读取得 blob 的公开
外层版本。当前外层格式已是 `0x400000005`，boot/vendor 字段与 A/B 配置有具体
差异；但尚未直接观察到此前 A/B 启动时安全世界实际命中的返回 PC。

改动仅为主机审计、只读采集器及文档。没有修改或构建新 UEFI、发送新的安全命令、
执行升级/生成/写回或设备重启；两个已归档候选的91文件绑定保持一致，M3/M4/M5未通过。

## 当前实机采集：版本与长度，非认证结果

用户手动进入TWRP并确认USB连接后，互斥检查无活动设备任务；采集器核对
fcde91e/recovery/fuxi/root/slot_a/release17，固定libqtikeymint.so SHA与参考匹配。
最终有效采集时间为2026-10-30 20:22:25 Asia/Shanghai，两个公开前缀快照及
stat/身份/库哈希前后稳定。证据为
[evidence/fuxi-m3-blob-public-20261030.json](evidence/fuxi-m3-blob-public-20261030.json)。

| 当前外层字段 | 读取值 | 边界 |
| --- | --- | --- |
| 格式版本 | 0x400000005 | 与固定TA最低格式相同，尚未认证 |
| OS version | 170000 | hardware授权map公开整数 |
| OS patch | 202610 | 不能与configure的原始YYYYMMDD直接判等 |
| vendor patch | 20260801 | 与A的20261005、B的20991231均不同 |
| boot patch | 202610 | 来自独立启动上下文的比较值，不是三字段configure输入 |
| algorithm | 32 | hardware公开枚举 |
| FBE tag | 未出现 | 不把普通包裹键当作convert存储键，也不伪造该标志 |

208字节文件中，采集按CBOR编码长度逐段读取到第四个外层item结束：每快照142字节，
后续66字节未请求。最终有效双快照读取总计284字节；不保存原始前缀、材料摘要、
加密尾部或未知授权内容，仅输出允许的整数与存在标记。没有调用KeyMint接口、
读取进程内存、挂载/remount或写入设备。TWRP自行进入时可能有的行为不属于采集器。

初版采集器误把第三个外层整数命名为flags并纳入本地摘要；其语义未确认，已从
本地摘要删除、初版标记无效。修正后重新采集并绑定新源码；最终证据不含该整数。
初版和重采各读两个142字节公开前缀，本轮合计568字节；均未请求后续加密item。
这不是原始blob或密钥材料的导出。当前文件与之前A/B启动所读文件的逐字节等价
**未证明**：此前候选不输出材料摘要，进入TWRP又是另一次启动，不将本次值倒填成
当时的真实TA输入或认证结果。

## 直接调用链更正

固定TA为此前LUN4核验的同一ELF，SHA256
`2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6`。
`0x310f`固定表项处理函数为`0x8984`。六条直接BL/尾跳指令已按机器码校验：

```text
begin 8984 --89e0--> 35154
                       --352d8--> 310a8 --310b4尾跳--> 31040
                                                           --31068--> 30d9c
30d9c --30e74--> 304dc（公开授权map解码）
      → 算法查找/认证边界 → 31010调用98c0（版本校验）
```

`0x35154`失败会直接返回给begin；成功之后才有begin中的操作函数指针调用。
所以此前“直接BL图不可达，只能通过8b1c/8db4的间接操作回调到版本门”的推断错误。
`0x3114`也不是这一校验链已验证的函数入口，不能凭相邻标签命名函数。

公开外层解析在认证前把三个外层整数与第四项授权bytes解入结构；硬件map中
OS/OS patch/boot/vendor四字段分别写入`+144/+14c/+1c0/+1b8`。
审计以公开合成envelope进入真实`30d9c`，在`25d4`算法查找之前停止；没有调用
认证回调。随后单独重新进入98c0是明确的反事实对照，不是伪造认证成功。

## 真实指令中的分支与字段来源

| 比较/返回点 | 内容 |
| --- | --- |
| 9908 | 非FBE结构格式小于dde0返回的0x400000005，返回-62 |
| 9944 | OS patch：b8ac有效getter与结构+14c比较，不等进入字段错误路径 |
| 994c | OS version：b82c与结构+144比较 |
| 9968 | boot patch：b850与结构+1c0比较（格式达到相关门槛时） |
| 9970 | vendor patch：b940与结构+1b8比较 |
| 9a1c | 上述字段错误路径返回-62 |

`b8ac`将本轮8位OS日期规范化为6位；A为202610、B为209912。
`b850`直接读取独立全局`5b4f4`，不是OS/vendor/OS patch三字段configure设置的值。
固定表项`0x208 → 0xbb7c`的处理链包含`bdf4`对该全局的写入；本轮只静态绑定
其代码，没有向手机发送0x208，没有构造或伪造启动参数。
其他三个getter受当前client选择影响，该client的真实运行时选择同样未采集。

两处-62立即数也不等于已经穷尽调用者可能传播的错误。解包中`30efc/30f58`
两个认证返回点会原样传播负状态；六组仅注入返回值的反例验证-62/-33/-38不被
改写，但没有证明相应认证函数实际能产生这些状态。未执行认证，不能据此给
实机增加一个已证实错误来源，也不能再声称“-62只可能来自98c0”。

## 已采集公开整数的离线重放

以下将公开整数放进合成envelope，用真实解码和版本门执行；不使用真实blob。
明确假设client0、新TA全局boot值为0，使用真实public configure解析器设置A/B。
对boot/vendor槽的局部改值仅为反事实定位，不是手机命令、候选修复或配置建议。

| 离线前提 | 首个不匹配 | 返回 |
| --- | --- | --- |
| A，boot假设0 | boot patch，9968 | -62，9a1c |
| B，boot假设0 | OS patch，9944 | -62，9a1c |
| A，额外假设boot已匹配 | vendor patch，9970 | -62，9a1c |
| A，仅额外匹配vendor | boot patch，9968 | -62，9a1c |
| A，同时假设boot/vendor匹配 | 无 | 0，仅局部版本门 |

因此现在有可复现的**字段不匹配路径**解释，并发现遗漏的独立boot上下文；
当前捕获的格式值也不支持“它本身格式过旧”的说法。但这些假设不是安全世界
运行时捕获，不能把表中返回PC写成先前A/B实机已命中PC，或用人造匹配值替代
真正初始化、认证/升级语义。TWRP自身可能通过keystore2升级/重试的旧证据依然
只证明代码存在，不证明本次metadata键执行过该路径。

## 检查、复现与剩余门槛

- 14组真实公开解码→独立版本门对照，覆盖两日期、格式、四字段和FBE合成反例。
- 4组相同合成envelope在A/B下重放：不同原因可得到同一-62/-62，不能靠状态唯一归因。
- 2组坏magic/截断的真实解析拒绝；6组错误返回点传播对照。
- 6组输入修改、认证/分配/导出边界、SMC与指令数上限拒绝。
- 5组本次公开整数的反事实重放；24项采集器流式边界、身份、库、竞态、CBOR异常、
  重复tag及报告白名单模拟检查。采集器字段与真实TA解码结果也有交叉核验。

所有检查退出0。固定Unicorn使用已有Python，在沙箱外私有内存运行；不安装依赖。
原始汇编/报告/有效及已清除未知值的无效初版记录在
`out/m3-begin-version-audit-v1/`，规范脱敏审计为
[evidence/fuxi-m3-begin-version-audit-20261030.json](evidence/fuxi-m3-begin-version-audit-20261030.json)。

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/test_fuxi_m3_blob_public.py \
  --report out/m3-begin-version-audit-v1/public-collector-tests.json
/Users/zhuxiaocheng/.pyenv/versions/3.12.3/bin/python3 tools/audit_fuxi_m3_begin_version.py \
  --partition out/m3-date-support-v1/keymaster-partition-verified.img \
  --public-evidence docs/evidence/fuxi-m3-blob-public-20261030.json \
  --output out/m3-begin-version-audit-v1
```

采集命令需已由用户进入TWRP、设备互斥及固定身份；输出已存在时拒绝覆盖：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/collect_fuxi_m3_blob_public.py \
  --serial fcde91e --output out/<新的独立目录>/twrp-public-envelope.json
```

下一门槛是审计真实boot上下文和client选择的初始化来源、封装及生命周期，并设计
同一次UEFI启动内仅公开字段的对照；在此之前不靠替换日期、补发208/setVersion、
升级或清除隔离来尝试过门。本轮不生成新启动候选。认证、真实密钥恢复、ICE/DUN、
userdata明文、M3/M4/M5与免USB重传均未通过。
