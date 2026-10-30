# KeyMint TA 的来源与名字：keymaster 分区只读取证 — 2026-10-28

## 方法

设备已在 Android 17（`custom_fuxi`、`user`、未 debuggable）下，`/vendor/firmware_mnt` 对 shell
是 `Permission denied`（vfat 以 uid=1000/gid=1000、dmask=0227 挂载）。本轮用设备自带的
`/system/bin/su` 执行 **只读** 命令：`ls`、`dd if=<分区> `（输出到主机，不在设备落盘）。
没有写分区、没有 remount、没有改属性。

## 关键发现

1. **存在专用 keymaster 分区**：`/dev/block/by-name/keymaster_a -> /dev/block/sde13`，
   `keymaster_b -> /dev/block/sde43`；分区大小 524288 字节。
2. 该分区内容就是 TA 本体：ELF64、little-endian、`e_type=DYN`、AArch64、`e_phnum=9`、
   `e_shnum=0`、入口 0；含 `DT_NEEDED libcmnlib.so` 与 `KEYMINT_BEGIN`、`KEYMINT_FINISH`、
   `KEYMINT_IMPORT_WRAPPED_KEY` 等命令字符串。
3. 镜像内的 TA 元数据（偏移 0x5a000）逐字为：

   ```
   keymaster64\0 1.0\0 None\0
   B=true;U=true;n=keymaster64;o=100;p=8:c47728cf3e4481,61,82:6224,b4,10a:9024,12d:1;s=96,47e\0
   ```

   其中 `n=keymaster64` 与 ELF 元数据首字段一致；`p=`/`s=` 未解释。
4. `/vendor/firmware_mnt/image` 的文件是 **UUID 命名** 的 `.mdt/.bXX` 分片；没有
   `keymaster64.bXX` 或 `keymaster.bXX`。搜索含 `keymaster` 字符串的分片只命中
   `fingerpr.b01` 与 `seccammi.b01`（其它 TA 的引用），不是 KeyMint 本体。
5. Android 侧 `android.hardware.security.keymint-service-qti`（`class early_hal`）与
   `qseecomd`、`vendor.qti.hardware.qseecom@1.0-service` 均在运行。检查时没有进程持有
   `sde13` 的 fd。
6. 本机只读镜像绑定：`keymaster-partition.img`，524288 字节，
   SHA256 `2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6`（保存在本目录，不入库，避免把厂商二进制提交进 Git）。

## 与 lookup 结果的关系

UEFI 探针从 **fastboot 临时启动**，此时 Android 还没运行。固定实现
`__qseecom_start_app` 的顺序是 `lookupTA` → 失败才 `firmware_request_from_smcinvoke`
（也就是把 TA 读进来再 `loadFromBuffer`）。在这个全新启动里 loader 没有已加载的
KeyMint app，`lookupTA("keymaster64")` 与 `("keymaster")` 都返回对象结果 2
（固定头定义 `OBJECT_ERROR_INVALID`），是可预期的“没有可复用的 app”，
**不是**“名字不存在”的证据——名字已由 TA 自身元数据确认为 `keymaster64`。

不能由此断言应用表是全局还是按客户端隔离；两种模型下“先 lookup 再 load”的顺序都成立。

## 下一步（未实现）

用 keymaster 分区里的 ELF 走 `loadFromBuffer`：

- op=1、counts=`0x1012`（BI2/BO1/OO1）：BI 为 ELF、BI 为文件名 `keymaster64`、
  BO 为 64 字节 distName 输出、OO 为 app 对象；
- 线格式：头 12 + 4×8 描述符 = 44 → 对齐 48；ELF 约 405 KiB 依次放入，消息页对齐后
  约 0x64000（100 页），另加 4 KiB 输出页；
- 需要扩展 M2 的 GPT 解析以取 `keymaster` 分区，并在一次分配中读入该分区后建桥；
- 失败时应看到 AppLoader 的具体错误（10..26），成功则返回远端 app 对象并可释放。

仍在边界内：不发送 KeyMint 命令、不读密钥、不转换、不写 ICE、不解密。

## 2026-10-30：历史 lookup / 实例推断边界补充

上文“全新启动里loader没有已加载app”是当时推断，不能作为已证事实。
lookup对象错误2只证明请求被拒绝，不证明应用表里没有TA；后来的loadFromBuffer
成功同样不证明实例新建或复用。见[SDK与会话生命周期核验](fuxi-m3-sdk-lifecycle-20261030.md)。
当前UEFI内部同App连续性在源码/模拟中已验证，ABL实例和boot上下文继承仍未知。
