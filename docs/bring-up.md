# SwiftUIHelloWorld bring-up — 2026-10-25

## 验证环境与结果

真机为 MRT-AL10，aarch64，`OpenHarmony-7.0.0.105`，HongMeng Kernel 1.13.0。
以普通签名 HAP `fun.oboard.hamintosh` 测试，未申请额外执行内存能力。

| 检查 | 结果 |
| --- | --- |
| ArkUI → 异步 N-API → C++ → Rust | `Hello from Rust` |
| 沙箱原始 ARM64 文件 `mmap(RX)` | `EACCES (13)`，未进入代码 |
| 沙箱 standalone Mach-O `mmap(RX)` | `EACCES (13)`，未进入代码 |
| 原始 Mach-O → ELF 代码段 → HAP 签名 | 原始入口返回 `42`，重复检查通过 |
| 目标 IPA → ELF 分段装载 | `mapped-awaiting-dyld`，各段内容与原文件逐字节相同 |
| Darwin ARM64 系统调用边界 | 真机 4 次陷入/返回通过，含 BSD carry 和 Mach 返回约定 |
| ARM64e PAC 指令 | PACIBSP/AUTIBSP、PACIA/BLRAA 在当前 HAP 密钥下返回 `42` |
| Darwin 初始栈 | 独立 RW 栈、保护页、16 字节对齐及目标 App 启动参数验证通过 |
| ARM64e chained rebase | 按真实槽位地址、key 和 diversity 重定位/签名，认证间接调用返回 `42` |
| 原版 iOS 27 dyld | 已在签名 ELF 中进入真实入口，正在逐项适配启动调用 |
| 目标 App 入口调用 / SwiftUI 输出 | 尚未进入 / 尚未验证，`appExecuted=false` |

AOT 探针中，`.incbin` 导入完整 Mach-O 文件；Rust 在装载后的 Mach-O 中查找
`LC_MAIN`，仅允许审计过的 `mov w0,#42; ret` 叶函数进入执行边界。
不存在用 ArkUI 静态文本替代目标 SwiftUI 的路径。

目标 App 使用独立的 AOT 段布局：`__TEXT`、`__DATA_CONST`、`__DATA`、`__LINKEDIT`
分别保留原始权限及相对于 `__TEXT` 的地址差。校验这些段不需要解析指针或调用入口。
chained fixups 仍保留原编码，尚未链接的 App 不可执行。

## 目标 IPA

输入为本机导出的 `SwiftUIHelloWorld.ipa`，最低 iOS 27.0，未加密，CPU subtype ARM64。

- Bundle ID：`devplaceholder.HDPAWPTN.SwiftUIHelloWorld`
- 原始可执行文件 SHA-256：`f110bf0414e3841c0a250f3b1598e71335882f1846c629ad2ef745b231f958da`
- `LC_MAIN.entryoff`：`0x44d4`
- 23 个直接动态库依赖、73 个未定义符号。
- 含 `LC_DYLD_CHAINED_FIXUPS`、`LC_DYLD_EXPORTS_TRIE`、`LC_BUILD_VERSION`。
- 动态链接器为 `/usr/lib/dyld`。

原始包与段分析输出位于被忽略的 `artifacts/imported/`、`artifacts/target-preflight.json`。
真机证据位于 `artifacts/device-compat-report.json`、`artifacts/gate0-device.log`、
`artifacts/harmonios-latest.jpeg`。HAP 构建同时通过 arm64-v8a 与 x86_64；
x86_64 只能检查文件，不能验证 ARM64 执行。

## Apple 运行库

本机可读取 Xcode 的 iOS 27.0 模拟器 RuntimeRoot，同时找到了更合适的真机运行库：

```text
~/Library/Developer/Xcode/iOS DeviceSupport/
  iPhone15,2 27.0.1 (24A446)/arm64e/Symbols/
```

其中包括带机器码的 dyld、SwiftUI、Swift Core、Objective-C runtime，覆盖目标 App
全部直接必需依赖。缺少的直接弱依赖为 `libPlaygrounds.dylib`。这不是完整的可启动
sysroot：尚未验证全部传递依赖、资源与服务，并且没有在此目录找到原始 dyld shared cache。
这批文件是 ARM64e；报告会列出 `pacImages`，不会把“文件存在”判为可执行。

进一步分析确认，其中的 dyld 保留了 cache 的地址布局：`LC_UNIXTHREAD` 入口文件偏移
`0x5a90`，全部映射段的跨度为 `0x15515c000`（约 5.33 GiB）。它的磁盘文件仅约
1.25 MiB，不能把文件紧密映射后按单一 slide 当作独立 dyld 使用；必须恢复原始 cache
布局，或取得独立的启动 dyld。检查器新增 `dyldLayout` 和相应阻塞项。

已取得 Apple 托管的 iOS 27.0 (24A437)、iPhone14,8 IPSW 中的
2.19 GiB 的 `SystemOS` AEA 成员以取得原始 cache。下载记录及断点文件保存在
`artifacts/ios27-download/`，只有 CRC32 校验通过后才会将 `.partial` 改为正式文件。
下载 CRC32 已通过，AEA 已解密并只读提取；原始 iOS 缓存共 78 个文件、4691 个映像，
缓存 UUID 与 VM 布局校验通过，文件保存在 `artifacts/ios27-system/cache/`。
本地原有 ipsw 工具较旧；已在 `artifacts/tools/ipsw` 放置并校验新下载工具的 SHA-256，
未替换系统安装。已从下载文件头解析 AEA 元数据并取得对应的公开 FCS 解密材料，
保存在同一个被忽略的下载目录中。

## Darwin 启动边界的新增实现

- Rust `bootstrap` 构造 `mach_header / argc / argv / envp / apple` 初始栈；
  C++ 分配带两端保护页的 RW 栈，汇编切换栈后验证目标 App 头、参数与返回。
- Rust `darwin::Process` 保存进程标识及最小 Mach 自身对象标识，提供无分配、无锁的调用分派。
  最初实现 `getpid`、`getppid`、task/thread/host self 标识；后续启动调用的适配见下节。
- 测试 Mach-O 的 `svc #0x80` 在 HAP 签名前被定点替换为专用 BRK；C++ 仅在已登记的
  guest 指令范围内接管该陷入，恢复结果、PC 和 NZCV。未知 BSD 调用返回 Darwin
  `ENOSYS=78` 并设置 carry；未知 Mach 调用返回 `KERN_NOT_SUPPORTED=46`。
  此路径没有把 Darwin syscall 号交给鸿蒙内核，也未修改目标 App 的机器码。
- PAC 证明当前硬件和进程支持所测指令；它不证明 Apple cache 内原先签名的指针可直接使用。
  重定位后的指针仍需按 storage address、key、diversity 重新签名，多线程与完整线程 ABI 仍待适配。

`appExecuted` 保持 `false`；原版 Apple dyld 的真实执行进度见下节，SwiftUI 尚未启动。

## 原版 dyld 按需启动

早期最小启动包中，`tools/pack_cache.py` 默认只选择缓存头和 dyld 的代码、数据页面，
不复制全套框架。首批 1,785,856 字节装入独立 `libhm_ioscache.so`，保留原始 VM 地址差。
末尾 NOBITS 段让 ELF 加载器预留整个 6,395,428,864 字节缓存地址区间；未选页面留在
预留区中，避免尚未装载的指针落入宿主的其他映射。约 644 MiB 的共享 LINKEDIT 暂缓装入。
`--pages tools/hello-world-cache-pages.json` 在默认启动页上叠加已经观察到的元数据访问：
ObjC 优化头、函数变体信息/表、预构建库索引，以及程序路径 trie。页面和范围均为缓存相对地址，
要求 16 KiB 对齐、位于实际映射内且缓存 UUID 匹配；缺失或冲突的选择会在生成 ELF 前拒绝。
索引按其真实结构长度选择；这不是全套 LINKEDIT 或框架的预装入。

`images` 记录 App 的 22 个可用直接依赖；缺少的弱依赖 `libPlaygrounds` 不伪造。
`reexports: true` 只沿 `LC_REEXPORT_DYLIB` 跟进符号查找所需的转出库，处理重复与环，
不是遍历所有传递依赖。增加启动实际调用的 `libc++abi` 后共 71 个映像；
早期 v2 产物补入公共跳转桩及 GOT、缓存头、线程局部变量和 ObjC 索引后约 413 MiB 的选中页，
6,530,111 项缓存重定位，其中 906,793 项带认证；完整缓存约 5.5 GiB。
各库导出 trie 从 `LC_DYLD_EXPORTS_TRIE`
定位并检查位于实际 LINKEDIT 文件范围内，仅选择对应页。`__OBJC_RO`、`__OBJC_RW`
作为共用大段继续暂缓。16 KiB 共用代码页还审计相邻映像的指令 section，按交集处理转接，
防止页内相邻库的 Darwin SVC 直接进入宿主内核；不扫描或改写数据字中的相似编码。
`stubs: true` 选择缓存标记为 `DYLD_CACHE_MAPPING_TEXT_STUBS` 的 34 个公共跳转区域，
约 9.2 MiB。它们不属于单个映像的 section；指令审计跳过各缓存文件首个元数据页。

最初的 `hm-cache-plan` 只读选中页的 v5 链，生成 3097 项重定位，含 1178 项认证指针。
C++ 按真实槽位地址签名；数据页在每次尝试前恢复原始值，代码页保持不可写。
缓存描述符 v2 把所选非执行页合并到一个只读数据块，启动时仅在本 ELF 已预留的对应范围
建立匿名 RW 页、复制原始字节、恢复计划权限，再进行缓存重定位。未选页保持预留状态；
不建立整块 6 GiB 的可写映射，也不尝试把匿名页改成可执行。
每次启动重新写入这些所选数据页，避免沿用前一次 dyld 修改过的函数变体指针。
链接产物会再次检查代码 PT_LOAD 地址/权限、数据块的只读归属、完整地址预留及各页 SHA-256。

真机曾拒绝 319 个程序头的稀疏 ELF（加载阶段 EACCES，尚未进入 dyld）。公开
[OpenHarmony 校验器](https://github.com/openharmony/kernel_linux_common_modules/blob/master/xpm/validator/elf_code_segment_info.c)
对程序头表大小设有限制。上述合并把当时产物降为 124 个程序头，真机恢复进入 dyld。
打包工具另对程序头表实施 16 KiB 的保守上限，在构建前暴露过多独立执行范围的问题。

### 当前 v3：签名代码与按需数据分页

当前选页清单启用 `lazyData: true`。描述符 v3 要求匹配的独立数据 pack：
签名 ELF 只保留 124,665,856 字节（118.89 MiB）RX 代码页及缓存地址预留，
不包含 eager 数据块或预生成的缓存重定位数组。此前 v2 的 413 MiB 数据选区、
6,530,111 项重定位统计属于历史产物。

`tools/pack_cache_data.py` 生成 2,329,690,112 字节（约 2.17 GiB）的
`cache-data.pack`，含 3428 个非执行映射。它保留原始映射数据、v5 slide 页起点、
逐 16 KiB 页 CRC，以及源代码映射中不含指令的 section 与映像头；后者以只读权限提供。
文件头校验 magic、UUID、首选地址、跨度、长度与索引 CRC，拒绝可执行数据映射。

首次读写缺页时，native pager 只在本缓存预留区内建立对应的匿名 RW 页、读取并校验
原始字节，再按原始 v5 链重定位。认证指针使用当前进程密钥和真实 storage address、
key、diversity 签名，最后恢复原始或 guest 已请求的权限。它不修改代码页，也不把
匿名数据变成可执行。已经被 guest 修改的页保持现状；每次新启动复位分页状态。

真机发现 OHOS musl 的整段 ELF 文件映射在稀疏 `PT_LOAD` 间洞留下可读别名，
导致 pager 没有收到某些本应发生的缺页。此前 libobjc 方法列表位于
cache-relative `0x47e4d80`，源数据 count 为 `5`，实际却读取到 ELF 同偏移
无关指令的 `0x52800000` 并触发 overflow。native 现在在 guest 进入前将所有
签名范围间洞设为 `PROT_NONE`。真机验证该 overflow 已消失，继续推进到后述 Mach 请求。

`tools/run_device.py` 在打包源码较新时重建数据 pack，检查本地 SHA-256、UUID 和大小，
使用 `hdc file send -b fun.oboard.hamintosh -z` 上传到应用私有的
`files/sysroot/cache-data.pack`。已上传记录匹配时按内容哈希复用，避免每次重传 2.17 GiB。
外部数据的传输成功不等于执行成功；启动前仍由 native 校验数据头及映射索引。

实际入口使用独立的磁盘版 dyld，不能直接冷启动缓存版：缓存版要求磁盘版先建立
`dyld_all_image_infos` 等进程状态。已通过 aria2 下载同一 IPSW 的 RestoreRamDisk，
其压缩数据 187,122,625 字节，平均速度 8.7 MiB/s；解压后 ZIP CRC32 `52ecc807` 验证通过。
`tools/extract_bootstrap.py` 解封 IM4P、只读挂载并复制 `/usr/lib/dyld` 后卸载镜像。
这个过程不需要下载另一个约 8.3 GB 的根文件系统。

提取的引导 dyld 为 1,447,088 字节，UUID `d3f59b02ee07371bb0913f150a078ed8` 与缓存版一致，
是独立的 iOS 27 `MH_DYLINKER`，没有外部导入。`tools/prepare_bootstrap.py` 检查 UUID、生成
系统调用/TSD 转接记录，并以独立段保留它的原始布局。每次执行前校验装载后的全部段字节，
随后由 Apple dyld 自己执行其 1835 处 chained fixup（含 657 处认证指针）；宿主不预先替它重定位。
`selfRebaseWitness` 在退出启动边界后检查其中一个常量指针是否已由编码值变成真实地址，
作为实际执行自重定位的证据，不等于验证了全部链接或 App 运行。

在 dyld 的指令 section 中，164 处 `svc #0x80` 转接到 Darwin 陷入，22 处 TPIDRRO_EL0
读取转接到 guest 的线程本地存储。记录在被忽略的 `artifacts/ios27-aot/package.json`，
原始 App 代码没有修改。宿主线程寄存器不替换为 guest 的线程指针。

真机已验证真正进入 dyld；依次遇到并适配了：

- Darwin commpage：固定地址的只读信息页，未实现的可选 CPU/时钟快路径不宣称支持。
- `mach_reply_port`：在进程的 Mach 名字空间分配独立接收权限。
- `thread_selfid`：使用实际执行线程的宿主线程 ID。
- platform syscall 的 cthread set/get 和 TPIDRRO_EL0 读取：维护独立 guest TSD。
- `mach_vm_protect`：仅转接登记的 guest 页面，验证权限和范围；数据映射采用私有 COW。
- `getentropy`：在已登记的可写 guest 内存中使用宿主真实随机源。
- `shared_region_check_np`：向 guest 返回实际的缓存预留基址。
- Mach send-right 引用计数和 `mach_port_mod_refs`，检查名称、引用下溢与溢出。
- `mach_port_construct` 支持普通接收端口、普通端口的初始发送权限与 `MPO_REPLY_PORT` 类型；
  类型保存在独立名字空间内，写回失败会释放尚未发布的对象。未支持的 guard、队列选项继续
  明确停止，报告捕获的原始 options，不把它们降为普通端口。完整消息 IPC 仍待实现。
- Mach absolute/continuous 时钟使用宿主单调/开机时钟，guest 时间单位为纳秒。
- 匿名 `mach_vm_map` / `mach_vm_allocate` 与整段 `mach_vm_deallocate`，按 16 KiB 对齐，
  分配、权限变化与写入均检查 guest 范围；匿名页不提供可执行权限。
- 初始 VFS 挂载原始 App 可执行文件，`open` 返回独立 guest 描述符，`F_GETPATH` 返回
  guest 文件路径；`close` 与进程销毁释放其宿主句柄。其他宿主描述符不可直接传入 guest 调用。
- VFS 只读根投影到已导入 sysroot，支持目录 `openat` 和 `dup`；路径逐级打开，不能越出根。
- `sysctl` 支持 `kern.bootargs` 的名字/长度查询，未提供的 MAC 策略命名返回 ENOENT；
  `sigprocmask` 维护 guest 掩码，SIGKILL/SIGSTOP 不可屏蔽，不修改宿主的信号掩码。
- 共享缓存动态配置使用独立只读页，按本次 dyld 的 v4 布局写入真机缓存文件的设备号与 inode，
  以及实际 guest 缓存路径。处理器变体标记保持未启用，覆盖扫描的 bitmap 不宣称有效。
  `fsgetpath` 仅为登记的文件标识返回对应虚拟路径，校验输出长度和 guest 内存。

未知 BSD 调用返回 ENOSYS/carry 并记录参数，让原版 dyld 处理可选调用失败；未知 Mach 调用、
显式 abort 或执行故障停在保护边界。设置 8192 次陷入上限，避免未实现行为形成无限循环。
真机报告字段为 `dyldBootstrap`，其成功进入不等于 App 已启动。

真机已越过 `sysctl`、根目录打开与共享缓存文件标识检查，并由独立 dyld 自行切换到缓存版。
2026-10-25 的早期启动完成 432 次陷入转接：host priority、host/clock MIG 调用、
`task_semaphore_create`、ARM64 absolute/continuous time trap、永久 Mach 内核端口复用、
Apple pthread 的 `ptr_munge` 启动参数及 Objective-C 消息发送惰性槽均已通过。
后续已推进到缓存线程局部变量与 Objective-C selector 初始化：

- `headers: true` 按每个映像的 `sizeofcmds` 选择映像头页面，未选择的代码页只作为只读
  数据装入；不会为 4691 个缓存映像逐一新增 ELF 程序头。
- `tlv: true` 解析全部缓存映像的 `S_THREAD_LOCAL_VARIABLES` section，检查 24 字节
  描述符、对齐和可写数据权限，只选择这些 section 所在页面。真机已越过先前位于
  `libwebrtc` 的 `__AUTH,__thread_vars` 缺页。
- `objcSelectors: true` 从优化头和 selector 哈希表计算索引大小与真实引用字符串范围，
  选择约 10.5 MiB 索引和 53 MiB 字符串，并按条目数、条目大小选择 HeaderInfoRO/RW
  和相对指针引用的 objc_image_info。随后加入 class/protocol 表、重复对象记录及其名称
  存储，已越过类名查询缺页。未重建或替换 Apple ObjC 索引。
- 公共跳转桩的 ADRP/ADD/LDR 序列还引用了独立的共用 GOT；现在按指令计算并选择
  627 页数据，约 9.8 MiB，避免已打包的跳转代码访问未选入的指针槽。
- 所选范围增加后，宿主与 Rust 的重定位范围查询均改用二分查找，避免逐条线性搜索
  数千个范围造成启动超时；动态配置页保持按地址排序，支持重复检查。
- 故障归属工具按 section 查找数据页的所属库；没有所属 section 的共用缓存元数据
  返回空值，不再将它误归到最近的代码映像。

`tools/run_device.py` 可从选页重打包、数据 pack 准备一直运行到截图采集，并检查打包工具和 Rust 源码的
修改时间。`--compressed-install` 可压缩传输含未压缩 native 库的签名 HAP，再由真机
`bm install` 安装；历史 v2 的一次 459,742,554 字节 HAP 传输实测为 56 秒；当前 v3 已缩减签名代码包。

`libobjc` 的 `_objc_init` 已实际调用并通过 `task_restartable_ranges_register`：
按 MIG 8000 格式接收最多 64 个 16 字节区间，校验 NDR、消息长度、flags、
地址溢出、重叠，以及包含 4096 在内的长度/恢复偏移边界；重复注册返回
`KERN_NOT_SUPPORTED`。陷入恢复时，仅在 PC 严格位于已登记区间内部才跳到恢复位置。
MIG 8001 同步适用于当前单 guest 线程模型，没有其他 guest 线程需要等待；
这不提供多线程运行支持。未知 Mach 请求仍停止尝试。

原始 App 的 CPU subtype 为 ARM64，其 ObjC class_ro、ISA、superclass 指针原先没有
ARM64e 签名。按原始 `__objc_classlist` 和 chained fixups 生成六个字段的适配清单：
本地目标必须落在已核验的 App 元数据内；外部 Class/Metaclass 必须是指定库的直接
数据导出，禁止 resolver/reexport、额外 addend、弱绑定及代码目标，并绑定缓存 UUID。
只有实际 AUTDA 的输入值、storage address 和 discriminator 全部匹配清单时，才签名
对应数据字段并重试原认证指令；其他认证失败继续停止。真机日志的 `-1001` 记录证明
class_ro 与 superclass 两处已完成此路径，App 机器码没有修改。

历史记录曾在 786 次转接时停于 ChronoServices 的 `__objc_nlclslist`
（cache-relative `0x6092b238`，页 `0x60928000`）；上述数据 pager 已继续处理此访问。
随后发生的方法列表 overflow 已通过段间空洞权限修复解决。
最新真机记录为 11,776 次转接。libdispatch 已完成 workqueue/workloop 初始化，
Darwin audit-token、debug-control port、guarded connection port、端口通知、memorystatus、
Mach-port 和 workloop 事件注册均已通过。`mach_msg2` 已能发送首次 XPC `w00t` check-in
以及后续向量消息；当前停在 reply port `0xd03` 的 `MACH_RCV_TIMED_OUT`，libdispatch
将其视为致命错误。要在外部 daemon 缺席时继续，必须实现本地 XPC service registry
或经过校验的 reply queue，而不能把超时改成成功。

宿主 `TPIDR_EL0` 低 12 位会泄漏 HarmonyOS 线程信息；缓存只改写了 libdispatch 的
三个已审计 CPU-number 读取点为 0，修复了 12 MiB heap 外的越界访问。其他线程指针和
TLS 读取保持原样。Darwin `gettimeofday`（116）、BSD `mprotect`（74）和定时
`__semwait_signal` 已在真机通过。`selfRebaseWitness=true`、`appExecuted=false`；
SwiftUI 尚未启动。

## 重定位与 cache 导入进度

- 新增 chained-fixup 解析，覆盖指针格式 1、2、6、9、12，以及三个 import table 格式。
  目标 App 的 73 个链位置中，13 个为内部 rebase、60 个为 bind，关联 56 个导入项。
  这与 nlist 中 73 个未定义符号是不同的统计口径。
- Bootstrap 重定位只接受无外部依赖的 `MH_DYLINKER`；在全部位置通过解析和验证后
  才写入数据段。App 的动态链接仍留给原版 Apple dyld。已用独立的自有 ARM64e
  Mach-O 在真机验证：按装载后槽地址与 diversity 生成 PAC，随后通过 `BLRAA` 调用；
  数据段复位后可重复运行。它没有进入原版 dyld 或目标 App。
- 新增现代 split-cache 读取和 VM→文件定位，校验分文件 UUID、权限、映射范围与映像地址；
  v5 slide 链按页流式遍历，不建立数千万项的常驻数组。使用本机 macOS 27 缓存做格式验证：
  80 个文件、101 个映射、4088 个映像；30,452,720 个指针位置中有 11,531,881 个带认证。
  macOS cache 只用于验证读取器；目标执行仍要求 iOS 设备缓存。
- `tools/extract_sysroot.py` 已作为一次性任务启动：确认下载进程存活，等待最终文件和下载
  元数据，复核完整 CRC32，然后解密、只读挂载并导入全部必需分缓存，再校验复制后的 UUID。
  该流程拒绝非 iOS 27 的缓存。状态在 `artifacts/ios27-system/extraction-status.json`，
  日志在 `artifacts/sysroot-extraction.log`；导入 cache 不等于运行时已完整。
- 原始 `.app` 已完整导入 HAP 的私有资源与手机的 `files/apps/SwiftUIHelloWorld.app/`，
  保留 `Info.plist`、资源与可执行文件字节，供后续主 bundle 和 VFS 读取。

新增命令：

```sh
cargo run --manifest-path runtime/Cargo.toml --bin hm-fixups -- '/path/to/AppExecutable'
cargo run --manifest-path runtime/Cargo.toml --bin hm-cache-info -- '/path/to/dyld_shared_cache_arm64e' --slides
```

当前检查点为 80 项 Rust 和 29 项 Python，覆盖缓存选页、只读数据块完整性与签名布局上限、
导出索引的文件/VM 地址转换与越界、转出库命令边界、链遍历、Mach 端口和描述符所有权、
kevent workqueue/workloop 控制、XPC 前置 RPC、connection port、端口通知、
文件标识查询的越界/错误路径、时钟和线程初始化边界。
构建及真机检查仍不代表 SwiftUI 已启动。

## 后续实施顺序

同日补充了同一进程内的重复启动修复。首次 dyld 会改写原始 App 的
`__DATA_CONST` / `__DATA`，此前再次点击检查会在 AOT 字节校验返回 `-5`，
显示 `layout-mismatch` 和 0 次转接。现在按生成的原始段表恢复可写页权限，
恢复文件数据并清零 BSS，再做完整字节校验；执行代码不参与复位。Native 诊断
从数据复位到执行串行化，防止并发请求改写正在运行的 guest。
真机同一宿主 PID 24970 首次记录 11,695 次转接，连续点击三次分别为
11,756、11,823、11,730；均重新进入 Apple dyld，并停在既有 XPC 超时点，
`appExecuted=false`。证据保存在忽略目录的 `repeated-launch-verification.json`、
`repeated-launch-1.json` 至 `repeated-launch-3.json` 和截图中。
新增测试覆盖数据/BSS 连续复位、代码损坏仍被拒绝及越界时不发生部分写入；
当前为 101 项 Rust、35 项 Python及 Clippy 通过。
报告另保留最后 48 字节 Mach 向量描述符，证实当前主消息大小为 1,960 字节、
辅助向量发送长度为 0；原有 1,064 字节的完整消息采集上限遗漏了这条主消息。

2026-10-26 恢复检查：已撤回未提交的消息队列实验，并重新构建、签名和安装
`ac1fdc8` 的运行时。HDC `-b` 的远端数据路径改为相对调试挂载目录，完整传入
2,329,690,112 字节数据 pack；沙箱访问可能提前启动应用，因此传输后再次强制停止，
再启动诊断。自动复测返回完整报告，记录 11,604 次转接，仍在相同
`libdispatch` cache PC `0x2eb2a974` 因 `MACH_RCV_TIMED_OUT` 停止 guest；
宿主 PID 14113 和诊断界面均保持可用，`appExecuted=false`。转接次数会随实际路径变化。
这次只恢复可重复诊断，没有完成 XPC 回复或 SwiftUI 启动。

设备工具另修复了零地址被误送入 cache 故障分析、系统日志无效 UTF-8 导致采集中断的问题。
报告未完成时保留进程查询、部分报告、运行时/系统日志和可用截图；未观察到 PID
不自动判定闪退。验证为 100 项 Rust、35 项 Python、Clippy，以及上述自动真机复测。

1. 实现本地 XPC service registry 与可校验的 reply queue，先完成 `w00t` check-in 和首个
   同步 reply；远程 daemon 不可用时必须交付结构化 XPC error，而不是 Mach receive timeout。
2. 按真实执行补齐线程/TLS、Darwin / Mach 和缓存传递依赖；原版 App 的链接仍由 Apple dyld 完成。
3. 验证原始 App 入口、Swift、Foundation 与 UIKit 的初始化，再按实际消息实现所需服务。
4. 将真实 CoreAnimation / IOSurface 输出连接 NativeWindow/XComponent，以真机 SwiftUI 界面验收。

逐库证据与静态报告字段解释见 [兼容清单](compatibility.md)。

## 参考项目的使用范围

- [HarmonyOS Agent Skills](https://gitcode.com/HarmonyOS_Skills/harmonyos-agent-skills)：查阅鸿蒙 Native、构建和设备知识。
- [harmonyos-skills](https://github.com/xiaowu5255/harmonyos-skills)：参考 N-API 线程边界、CMake/Cargo 协同。
  Rust 预编译 std 的可用性以当前 [rustc 官方说明](https://doc.rust-lang.org/rustc/platform-support/openharmony.html) 和实际构建为准。
- [harmonyos-device-automation](https://github.com/web-infra-dev/midscene-skills/blob/main/skills/harmony-automation/SKILL.md)：查阅截图、启动与验证流程。
  本轮使用 HDC 确定性命令及截图检查，没有调用需要视觉模型密钥的 Midscene 推理。
- [HiSH](https://github.com/harmoninux/HiSH)：研究手机可执行内存约束与签名包路径；没有引入 QEMU。
- [UniXNU](https://github.com/UniXNU/UniXNU)：研究完整 XNU/UEFI 路线与私有 blob 分离方式；没有更改设备启动链。
- [Apple Mach-O 定义](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)、
  [dyld chained fixups](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h)：格式核对。
- [Apple dyld 启动流程](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)、
  [ARM commpage 布局](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/arm/cpu_capabilities.h)、
  [Mach trap 定义](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_traps.h)：启动与内核 ABI 核对。
- [XNU 可重启区间接口](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/restartable.defs)、
  [区间布局与边界](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/restartable.h)：Mach 请求与恢复 PC 语义核对。
- [ObjC 指针认证常量](https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc-config.h)：
  class_ro、ISA、superclass 的签名 key 与 discriminator 核对。

未复制这些参考仓库的实现代码；本轮新增运行时与工具均在本工程中编写。
