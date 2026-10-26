
# 果易通

**Harmonios**

> 在 HarmonyOS 设备上原生执行 ARM64 iOS 应用的实验性兼容层。

架构见 [v1 方案](docs/v1.md)。当前已打通 ArkUI → C++ → Rust，完成真机 Gate 0、
Mach-O 检查器、Mach-O → 签名 ELF 探针，以及目标 IPA 的原始段装载和逐字节校验。
**SwiftUIHelloWorld 尚未运行**；原版 iOS 27 dyld 已在真机开始执行，仍需补齐它实际请求的
Darwin/Mach 接口及后续 SwiftUI、图形输出。

2026-10-25 的 MRT-AL10 真机结果：外部代码文件和 Mach-O 的 RX 映射均被拒绝
（`EACCES=13`）；将原始 Mach-O 嵌入 HAP 签名 ELF 后，入口成功返回 `42`。
目标 App 的 ARM64 段已按原始相对地址装入 ELF，状态为 `mapped-awaiting-dyld`。
这项结果选择了 v1 的 AOT 路线，不代表 SwiftUI 已启动。

## 构建与验证

需要 DevEco Studio 的 SDK、Node、Java、hvigor/HDC，以及 Rust、Python 3。
本机签名沿用 DevEco 的 `build-profile.json5`，不要提交私有签名材料。

项目与模块已使用 Harmonios 名称；调试 bundle ID 暂保留 `fun.oboard.hamintosh`，
因为当前本地签名 profile 绑定该 ID。重新签发 profile 后再同步修改部署标识。

```sh
rustup target add aarch64-unknown-linux-ohos x86_64-unknown-linux-ohos
python3 tools/prepare_ipa.py '/path/to/SwiftUIHelloWorld.ipa'
python3 tools/run_device.py
```

`run_device.py` 会在 cache 选页清单或打包源码更新时自动重打包，并准备非执行数据 pack。
它在安装、强制停止后用 HDC 向应用私有目录传输数据；UUID、文件大小和 SHA-256 与
上次记录一致时复用已上传文件。传输使用 `hdc file send -b fun.oboard.hamintosh -z`。
该命令的远端路径相对于 HDC 调试挂载目录，使用
`data/storage/el2/base/haps/harmonios/files/sysroot/cache-data.pack`，不加开头的 `/`。
随后启动并轮询完整诊断，完成后立即抓图，不依赖固定等待时间。每次运行还会把故障 PC、所属库、
原始 cache 地址、16 KiB 页及选页状态写入 `artifacts/fault-analysis.json`。也可单独分析：

```sh
python3 tools/run_device.py --skip-build --skip-install
python3 tools/run_device.py --no-clean
python3 tools/run_device.py --compressed-install
python3 tools/analyze_device_fault.py
```

应用启动后自动运行检查；可以重复点击“重新检查启动条件”。报告在应用沙箱的
`files/compat-report.json`，也可用采集工具从诊断日志重建到
`artifacts/device-compat-report.json`，并获取真机截图。
若诊断超时而未生成完整报告，工具会保存 `artifacts/incomplete-run.json`、
未完成的报告日志、进程查询结果、运行时及系统日志，并尝试抓图。
`processObservedAlive` 只记录查询时是否看到有效 PID；未看到 PID 本身不能证明闪退。

```sh
cargo test --manifest-path runtime/Cargo.toml
cargo clippy --manifest-path runtime/Cargo.toml --all-targets -- -D warnings
python3 -m unittest discover -s tests -p 'test_*.py'
cargo run --manifest-path runtime/Cargo.toml --bin hm-inspect -- '/path/to/AppExecutable' '/path/to/iOS-device-sysroot'
```

检查器退出码：`3` 表示解析完成但启动条件未满足，`2` 表示参数、文件或格式错误。
`requiredImports` 是待解析的导入列表，`missingSymbols` 只有实际链接后才能确定；
静态预检查的 `symbolResolutionAttempted=false`、`loadedImages=0`、`appExecuted=false`；
原版 dyld 的实际执行单独记录在 `dyldBootstrap`。
`missingStandaloneImages` 仅表示 sysroot 下没有独立文件；`cacheResolutionAttempted=false`
表示这份静态检查没有查询共享缓存，不能将该列表当成运行库缺失。
存在运行库文件只代表找到文件，不代表已解决传递依赖、重定位或平台兼容。

进一步的真机验证已通过 Darwin syscall 陷入/返回、ARM64e PAC 指令和 Darwin 初始栈。
它们是启动 Apple dyld 所需的执行边界；完整 Mach IPC、框架绑定与 App 启动仍待完成。
Bootstrap 的 chained rebase/PAC 签名也已通过真机认证调用验证；目标 App 的绑定由原版 dyld 处理。
`hm-fixups` 可分析链，`hm-cache-info --slides` 可验证 split-cache 布局及 v5 重定位信息。

完整 iOS 27 缓存已导入本地。`tools/hello-world-cache-pages.json` 绑定缓存 UUID，
选择原始 App 的 22 个可用直接依赖、实际请求的 `libc++abi`，并沿
`LC_REEXPORT_DYLIB` 跟进符号查找，共 71 个映像，含约 9.2 MiB 公共跳转桩。
当前描述符 v3 使用 `lazyData: true`：签名 ELF 只带约 119 MiB 的 RX 页，
保留 6,395,428,864 字节的缓存地址跨度；非执行内容存入约 2.17 GiB 的
`cache-data.pack`，不再把数百万项重定位记录及重复数据装入 HAP。

`tools/pack_cache_data.py` 保留原始非执行映射、映像头和无指令 section 的只读元数据。
首次访问时，native pager 校验 16 KiB 页的 CRC，按原始 v5 链重定位并按真实槽位地址、
key、diversity 生成 PAC，再恢复原页权限。数据 pack 不授予执行权限；已经装入并被
运行库修改的页不会再次覆盖。每次尝试前清理本次匿名数据页，避免沿用上次进程状态。
未选择的代码仍需加入签名 ELF，不能依靠 data pager 执行。

OHOS ELF 装载器会在稀疏 `PT_LOAD` 之间留下整段文件映射的可读别名。
native 层已在进入 guest 前将这些空洞设为 `PROT_NONE`，保证后续读取确实触发
原始数据分页。此前 ObjC 列表 overflow 中的 `0x52800000` 与该别名中的无关指令吻合；
这项修复已在真机消除该 overflow，继续推进到 task MIG 3409。
实际启动记录在真机报告的 `dyldBootstrap` 中。未知 BSD 调用返回真实 ENOSYS/carry 并记录，
允许 dyld 自行处理可选功能失败；未知 Mach 调用、abort 和执行故障停止该次尝试。
另从同一 IPSW 的 RestoreRamDisk 提取了 1.4 MiB 的独立引导 dyld，UUID 与缓存版相同。
它先完成自身重定位与进程初始化，再负责切换到缓存中的 dyld；这次切换已经在真机发生。
当前已越过库符号和函数变体解析、缓存线程局部变量描述符初始化，
正在推进 Objective-C 初始化，目标 App 入口尚未执行。
原始 ARM64 App 的六个 ObjC 类元数据字段另有明确的 ARM64e 签名适配清单，
绑定目标按缓存导出 trie 和 UUID 核验；真机已通过 class_ro 与 superclass 的认证重试。
此前 ChronoServices 的 `__objc_nlclslist` 缺页已由数据 pager 继续推进；
最新在 908 次转接后停于 task MIG 3409（36 字节请求），尚未显示 SwiftUI。逐库状态见 [兼容清单](docs/compatibility.md)。

```sh
python3 tools/pack_cache_data.py artifacts/ios27-system/cache/dyld_shared_cache_arm64e artifacts/ios27-data/cache-data.pack
python3 tools/pack_cache.py artifacts/ios27-system/cache/dyld_shared_cache_arm64e artifacts/ios27-aot \
  --clang /Applications/DevEco-Studio.app/Contents/sdk/default/hms/native/BiSheng/bin/clang \
  --pages tools/hello-world-cache-pages.json
```

随后重新构建 HAP，构建系统会纳入这份独立缓存 ELF。仅有原始缓存或打包成功不代表 App 启动。

## 本地文件

- `runtime/`：有边界检查的 ARM64 / Universal Mach-O 解析、兼容报告和 C ABI。
- `native/`：受限的执行探针、信号保护和与 Rust 的 ABI 契约。
- `tools/prepare_ipa.py`：校验 IPA 路径、导入目标和生成可审计探针。
- `tools/pack_probe.py`：把完整的 return-42 Mach-O 原样装入 ELF 代码段。
- `tools/pack_macho.py`：保留目标 App 段间地址差、生成 ELF 段布局；不处理 iOS 动态链接。
- `tools/pack_cache.py`：按需选取原始缓存代码页、保留地址跨度，并验证生成 ELF 的布局与字节。
- `tools/pack_cache_data.py`：生成带 UUID、索引校验、逐页 CRC 与原始 slide 信息的非执行数据 pack。
- `tools/fetch_zip_member.py`：从 IPSW 断点下载指定的未压缩 ZIP 成员，完成后校验 CRC32。
- `tools/fetch_zip_member_aria2.py`：让 aria2 并发下载单个 IPSW 成员，支持 ZIP deflate 与 CRC 校验。
- `tools/extract_bootstrap.py`：从已校验恢复镜像中只读提取与缓存 UUID 一致的独立 dyld。
- `docs/bring-up.md`：实测证据、运行库来源与下一步。

IPA、提取的 App、Apple 运行库、下载缓存和构建产物均留在 Git 忽略的目录中。
