# Harmonios 架构复盘与加速路线

评估日期：2026-10-30。范围：原始 ARM64 IPA 在 HarmonyOS 本机运行，包含图形、输入、网络、存储与效率。本文是路线建议，没有把源码移植或宿主重画 UI 当成 IPA 兼容完成。

## 结论

保留 Mach-O/AOT 工具链、Rust Darwin 内核和 NativeWindow 出口；停止把 `execution_probe.cpp` 的场景补丁与 `renderInContext:` 当成正式运行架构。优先建立可在 Mac 测试的运行内核与平台接口，再以限时实验决定图形后端。最值得实测的组合是 Darling 的 Metal ABI 外壳与 Indium/metal2vulkan 后端，而不是自写完整 Metal。

没有发现可以直接嵌入 HarmonyOS、完整兼容 iOS 27 SwiftUI IPA 的现成项目。已有开源组件能缩短部分工作，但没有消除 CoreAnimation、IOSurface、线程语义和私有协议这些整合成本。不能承诺换一个库就完成项目。

## 当前实际边界

本轮基于当前工作区核对，不能把聊天中曾做过的实验当成当前能力。当前 HEAD 为 `82e40b4`，工作区另有 `execution_probe.cpp` 的本地实验修改。

| 子系统 | 当前可复用部分 | 尚未成立的能力 |
|---|---|---|
| 执行 | Mach-O、原版 dyld 引导、签名 ELF、缓存选页、PAC/TSD 适配 | 通用重编译器、长期稳定的生产运行循环 |
| 调度/服务 | Rust MIG、端口、XPC、workqueue/workloop、部分本地服务 | 完整消息等待/唤醒、完整系统服务语义、稳定 guest 主线程生命周期 |
| 图形 | ArkUI XComponent→NativeWindow、BGRA 提交、来源诊断 | 正式 CA commit→compositor→present；仓库没有 Metal→Vulkan 集成 |
| 输入/屏幕 | 宿主窗口与触摸来源可用 | 当前源码没有完整 guest 输入投递及安全区桥接；历史防崩实验不等于可交互 |
| 网络 | 尚未找到完整 socket/connect/send/recv 调度链 | DNS、TCP、TLS、URLSession 等端到端能力 |
| 存储 | guest FD 表、只读 bundle/sysroot、read/pread/stat/mmap/目录读取 | Documents/Library/tmp 可写挂载、普通文件写入、rename/fsync/锁、SQLite 与偏好持久化 |
| 效率 | 原生 ARM64 执行、已有 direct-call 桩、HSP 和缓存复用 | 大量 BRK/TSD 信号热路径仍在；快照/整包资源同步开销尚未系统测量 |

最新 `physical-window-ivars` 等报告仍有 `dyld-execution-fault`，即使有一条帧记录也不能说明完整 UI 已正确显示。现有 `execution_probe.cpp` 约 3273 行，混合启动、信号处理、线程、场景构造、图形和诊断；这是迭代难以收敛的重要原因。

## 建议的目标分层

```text
ArkUI 窗口、Surface、触摸、避让区、生命周期
                    ↓ Host API（普通 C ABI）
Host Backend: Mac / Harmony / Headless
                    ↕
GuestSession：线程、事件队列、端口、VFS、时钟、服务路由
                    ↕
Mach-O + 原版 dyld / Swift / ObjC / 选定 Apple frameworks
                    ↓
Graphics bridge：CA transaction / IOSurface / Metal ABI
                    ↓
图形后端 → Mac 离屏纹理或 Harmony NativeWindow
```

模块应能独立验证，不能把信号处理器当成运行时总调度器：

- `runtime-core`：ABI、端口、FD、VM 元数据、事件和服务协议，保留现有 Rust 实现。
- `guest-session`：创建/销毁、guest 主线程、worker、暂停/恢复、输入队列、回调队列。诊断超时属于测试 harness，不得定义应用寿命。
- `host-api`：线程/等待、文件/套接字、时钟、日志、显示、输入、表面。提供 Mac、Harmony、headless 实现；无需把所有本地 syscalls 都发到独立 IPC server。
- `graphics`：资源与帧提交、图形 backend、上下文/同步。GPU 边界不承担 UIKit 布局。
- `diagnostics`：采样、栈、trace、报告单独收口；热路径默认关闭格式化和逐调用日志。

## 图形：先验证最难的接缝

正式目标应是复用 Apple 上层框架的实际事务/绘制，替换平台依赖与 GPU 出口。`renderInContext:` 保留作离屏诊断，不能承担现代 SwiftUI、SDF、portal、Liquid Glass 的通用合成承诺。

候选 A：Darling Metal ABI 层 + Indium/Iridium。Darling 的 Objective-C Metal 实现确实存在，源码使用 Indium，包含资源、队列、encoders 和基础示例；仍有缺口，不能把“ABI-compatible”描述解释成已覆盖 iOS 27 的全部私有 ABI。Indium 当前要求 Vulkan 1.3 和 timeline semaphore；实际手机特性必须查询。

候选 B：薄 Metal ABI 层 + steelbrain/metal2vulkan。当前上游 README 为 Beta，runtime API 仍不稳定；从 AIR/metallib 转 SPIR-V，提供 Rust GPU runtime，要求 Vulkan 1.2 与 timelineSemaphore，Rust 1.98+。它不是现成的 Objective-C Metal.framework，没有 MSL 源码编译器；预编译 metallib 与运行时生成 shader 必须分别验证。不要同时把 Indium 和 metal2vulkan 接入正式资源管理，先用同一组 fixture 比较后选一条。

两条候选都还缺 Harmonios 整合：同一 ObjC runtime 下的对象身份/Blocks/retain-release，iOS 私有 selectors，IOSurface 与外部内存，CA context/commit，资源与 fence 生命周期，以及 OHOS WSI。仅让 MTLCreateSystemDefaultDevice 非空或画出三角形不算过关。

建议用 5–10 个工程日作为图形可行性验证的预算，而不是项目完成日期：

1. 查询真机 Vulkan 特性；固定一个上游 commit，先跑 offscreen compute/render fixture。
2. 用真实 QuartzCore/目标 app 所需的代表性 metallib 验证解析、编译、纹理、混合、采样、同步；不能仅使用转译器自造示例。
3. 在不启动完整 App 的 harness 中创建最小 Apple layer/text/gradient，证明真实事务能到达候选 GPU 后端并得到正确像素。
4. 记录所缺 SPI/着色器特性/IOSurface 接口，估算缺口，再决定是否接入 Gallery。

若第 3 步不能完成，就应承认图形路线尚未成立。可以选择专门的 2D 子集路线（CoreGraphics/CoreText→Skia/FreeType/HarfBuzz 或 Harmony Drawing），但这意味着实现框架 ABI 和合成语义，且不能自动保留 Liquid Glass；应作为独立产品范围决策，而非默默替代原目标。换用 Skia不会自动让原版 SwiftUI 产生可执行 DisplayList。

## 输入、窗口与安全区

宿主只生成统一 InputEvent（pointer ID、phase、timestamp、位置、pressure、取消）并入队。guest 主线程在正常事件循环取队列，通过选定的 UIKit/HID 入口创建和交付真实事件。手势 begin/move/end 必须保持同一触点身份；completion、定时器、网络和文件回调也必须走规定的 guest 队列。

ArkUI 线程不得直接进入 guest UIKit。拒绝输入能止崩，但不能计为输入支持；抓信号后继续也不应是正式输入路径。

建立一个 `DisplayMetrics`，统一 physical px、host vp、guest pt、scale、rotation、safe insets 和 surface generation。一个变换矩阵用于绘制，逆矩阵用于输入。把 inset 注入 guest 场景/窗口的真实安全区模型；root controller 的 additionalSafeAreaInsets 可作阶段性办法，必须与已有 inset 比较并测试嵌套导航、键盘和旋转。消除 1272×2860、3.5 的散落硬编码。

输入门槛：Mac 回放验证顺序、取消、坐标与线程归属；iOS Simulator 对照验证按钮/滑动/多指；Harmony 点击 100 次、切后台再恢复、旋转后命中正确，且输入后真正改变 guest 状态。

## 网络与存储：建立共享的 FD / 异步基础

网络先走 Darwin socket ABI→host BSD/POSIX sockets，不要自写 TCP。实现 sockaddr、errno、socket option、fcntl/nonblocking、DNS、read/write readiness 与取消。Mac 使用 kqueue，Harmony 使用 epoll/eventfd 或 NDK 对应机制，抽象相同的 readiness 模型。Apple 的 kevent64/workloop、Mach ports 不等于普通 BSD kevent，不能整体交给 libkqueue。

然后测试原版 CFNetwork/URLSession；它还依赖代理配置、TLS 信任、DNS 与系统服务，socket 成功不等于 URLSession 成功。只有确认这条路成本过高，才增加窄的 NSURLSession/CFHTTP 宿主适配，以 libcurl 等处理 HTTP，并将 callback 返回 guest 队列。swift-corelibs-foundation 的 URLSession 可作实现参考，其 Swift/ObjC ABI 不能直接替换 iOS Foundation。

网络门槛：本地 echo、DNS、可信 HTTPS、重定向、取消、超时、断网恢复及并发回调，无需以公网是否稳定作为测试条件。

存储保留统一 FD 表，但增加对象类型（regular/directory/socket/event）和权限、位置/锁状态。挂载分为 bundle/sysroot 只读，以及每 App 的 Documents、Library、tmp 可写。补 O_CREAT/write/pwrite/truncate/rename/unlink/fsync 与 fcntl/文件锁；路径解析与 guest 路径身份在同一层。用临时目录在 Mac 测同一套实现。SQLite WAL/回滚/锁、NSUserDefaults 重启持久化，是比“写一个文件”更有效的门槛。Darling 的 prefix/VFS 思路可借鉴，不能简单把全部宿主路径暴露给 guest。

## 运行效率与迭代效率

先测 trace 中的真实热点：trap 类型占比、TLS 访问、Mach 空转、guestGate 等待、图形 CPU 时间、buffer copy、启动与安装耗时。不要根据 ARM64 原生执行就宣称接近原生性能。

1. 对高频 TSD 访问和已验证的 syscall wrapper 建 AOT 直接桥；已有 direct-call 桩只是起点。必须完整保持 Darwin 返回寄存器、carry/NZCV、错误码、栈对齐和 TSD/线程上下文。不能粗暴把任意 SVC 改为普通 BL。
2. 真正等待消息/FD/定时器，减少“无消息就立即超时”的轮询；等待时正确释放 guest 执行权。未测之前不要直接删除所有 guestGate 锁。
3. 图形按 transaction/dirty 更新，复用纹理和字形缓存；先持久纹理，再评估 IOSurface/NativeBuffer 导入和零拷贝。
4. 保留已有 HSP/审计缓存复用；资源按内容哈希同步，字体/sysroot 不应每轮重传与重写。运行测试包与真实应用资源分离。
5. 每次报告保存 App/cache UUID、内容哈希、依赖版本、设备、图形特性与实际后端，阻止“测试错 IPA”重现。

## Mac 优先测试架构

目标是让多数问题在交叉编译前暴露。80%–90% 的普通迭代在 Mac 完成可作为流程目标，当前并未测得这个比例。

本轮 Mac 实测基线：`cargo test --manifest-path runtime/Cargo.toml --lib` 为 148 passed、0 failed、1 ignored（该项要求本地未提交的设备捕获）；编译 5.79 秒，执行 0.33 秒。`python3 -m unittest discover -s tests -p test_renderer.py` 两项通过，耗时 3.569 秒。它们覆盖现有模块边界，不代表文字、输入或整个 App 已通过。

| 层次 | 在 Mac 上做什么 | 能证明什么 / 不能证明什么 |
|---|---|---|
| L0 纯逻辑 | Rust ABI/端口/XPC/VFS/调度状态机；C++ 像素/坐标/生命周期测试 | 无需 Harmony SDK、签名、安装；不能证明驱动与系统集成 |
| L1 回放 | 规范化 Mach/XPC/FD/输入 trace，fake clock、fake I/O，断言消息、状态与唤醒因果 | 重现历史失败；不能把固定回复回放当成新服务已实现 |
| L2 平台后端 | Mac 真实文件/Socket/kqueue；headless 表面、帧数据与资源释放 | 验证真实 I/O 和线程行为；内核 4/16 KiB 差异需显式模拟 |
| L3 Apple 对照 | iOS Simulator 跑自有最小 UIKit/SwiftUI fixture，输出图片、触摸状态、文本 glyph/布局；Mac Metal 跑 shader oracle | 原生行为作为参考；须匹配 OS/字体/scale，不能把 iOS device IPA 直接当 simulator app |
| L4 转译图形 | 相同 shader/场景通过 Vulkan→MoltenVK→Apple GPU，比较离屏像素/数值/资源行为 | 便于 Mac 调试 Metal→Vulkan；MoltenVK 可能掩盖手机 Vulkan 特性缺口，不能当作 Mali/Adreno 证明 |
| L5 Harmony | WSI、NativeBuffer/fence、手机 GPU、输入/安全区/生命周期、同一 IPA E2E | 集成门槛与最终画面验收；仅在前面通过后执行 |

Mac 的 host API 不能偷偷直通同名 Darwin syscall，绕过兼容层后让测试虚假通过；测试应从 guest 调度入口进入，明确选择 Mac backend。不要把 guest libobjc/Foundation 全局塞进普通 macOS 进程，与 host runtime 混用。完整 AOT guest 的 Mac 执行 harness 是单独移植工作，不是前三层测试的前置条件。

渲染测试先在 Mac 生成可序列化中间帧/命令，然后 headless backend 比较；通过后用 Harmony backend 消费同一输入。UIKit/SwiftUI 原生 oracle 用自有源码 fixture，原始第三方 IPA 最终仍在 Harmony 验收。

建议命令接口（规划，尚未实现）：`hm-test abi`、`hm-test replay <trace>`、`hm-test graphics --backend headless|mac-vulkan`、`hm-test oracle --simulator <runtime>`、`hm-test device-smoke`。不要重新制造与现有 cargo/test CLI 重复的工具，只加统一编排与证据清单。

## 开源组件选择与边界

| 项目 | 复用价值 | 关键边界 |
|---|---|---|
| Darling / darlingserver | Mach/POSIX/VFS、等待和线程/服务设计、兼容测试参考 | macOS/Linux 目标；不是可安装的现代 iOS 兼容层；whole-server 引入不一定更快 |
| darling-metal + Indium/Iridium | ObjC Metal ABI 外壳、Vulkan 资源与 AIR 转译 | 私有 iOS Metal/CA ABI 需另测，Indium 当前 Vulkan 1.3；有未完成项 |
| steelbrain/metal2vulkan | Rust AIR 前端、SPIR-V、GPU runtime；与现有 Rust 易接 | Git 固定 revision；Beta、不含 ObjC facade/MSL compiler；手机能力需实测 |
| reims-vgpu | GPU 命令序列化、资源生命周期与批量提交参考 | macOS VM 的虚拟 GPU，不能直接塞进 Harmony HAP 运行 UIKit |
| touchHLE | 环境分层、输入、文件沙箱、测试方法 | 项目明确面向早期 32 位 iOS，并明确不以 64 位 iOS 为目标 |
| Skia / FreeType / HarfBuzz | 若选 2D 替代路线，复用栅格/字体/排版 | 不负责 UIKit/SwiftUI/CA ABI 和 DisplayList 提取 |
| libkqueue | 普通 BSD readiness 语义参考与测试 | 文档承认行为差异；不能覆盖 Darwin workloop/Mach 语义 |
| swift-corelibs-foundation / libcurl | URLSession 异步分层与 HTTP 实现参考 | 非 Darwin 源码兼容实现；不是 iOS Foundation 二进制替换 |
| OpenSwiftUI / SkipUI | 有源码时可研究的另一条移植路线 | 源码兼容/Android 平台，不是原 IPA 二进制兼容，也不是现成 Harmony backend |

MoltenVK 的方向是 Vulkan→Metal；它适合 Mac 上测试 Vulkan 后端，不能充当 Harmony 上 Metal→Vulkan 的实现。

核查版本：metal2vulkan HEAD `219f01365dc4c8eb346816c405b5b17403793764`；darling-metal 本地浅克隆 `a55b9507a97fab22a927fe007de46fc9924f9b47`；Indium HEAD `8423a7d2f053167030d2bc4a227f96243c740667`。上游变化较快，正式依赖需固定并重新验证。观察到的许可分别包括 metal2vulkan 的 GPL-2.0-or-later OR LGPL-3.0-or-later、darling-metal 的 MPL-2.0、Indium 的 0BSD；不能把整个 Darling 的许可自动套到所有子模块。

## 实施顺序与验收

1. **先建立 Mac 快速闭环**：冻结 App/cache 身份；从探针抽出 session/host API；将现有 ABI、文件、像素测试纳入统一报告；捕获一个可回放的失败。验收：改一个状态机后无需构建 HAP 就能复现与验证。
2. **图形可行性先行，同时补事件循环**：按前述最小真实 Apple 图形 fixture 选择一个 GPU 后端；guest 主线程队列和真实等待先稳定。图形若失败及时调整范围，避免先铺满网络/存储后才发现核心 UI 路线不通。
3. **输入与持久化闭环**：点击改变状态、滑动、取消、屏幕/安全区变化；偏好与 SQLite 重启保留。验收必须观察 guest 状态变化，不能只检查进程没崩。
4. **网络闭环**：TCP→HTTPS→URLSession，所有回调遵循同一调度契约。
5. **目标 Gallery 与效率验收**：原 IPA 的真实文字/渐变/卡片/导航/材质完整显示；反复输入和前后台恢复稳定；测帧时间分位数、空闲 CPU、启动与 RSS，再优化热点。

每阶段都应有可重放输入、预期状态、超时、依赖哈希和失败产物。新增 syscall 数量、返回非空对象、有非透明像素，都不是产品完成指标。

如果可以接受取得源码并重编译，源码移植通常是更短的交付路线；如果原 IPA 与现代 SwiftUI 行为必须保留，则上述兼容层仍是系统工程，开源复用能减少工作量但不能把它变成短期 UI 修补。完整 iOS 虚拟机、远程流式界面也不应作为未声明的替代目标。

## 核查来源

- [Darling](https://github.com/darlinghq/darling)；[syscall 设计](https://docs.darlinghq.org/internals/basics/system-call-emulation.html)；[darlingserver](https://github.com/darlinghq/darlingserver)
- [darling-metal](https://github.com/darlinghq/darling-metal)；[MTLDevice 实现](https://github.com/darlinghq/darling-metal/blob/main/src/Metal/MTLDevice.mm)；[Indium](https://github.com/darlinghq/indium)
- [metal2vulkan](https://github.com/steelbrain/metal2vulkan)；[runtime](https://github.com/steelbrain/metal2vulkan/blob/master/crates/metal2vulkan-runtime/README.md)；[validation](https://github.com/steelbrain/metal2vulkan/blob/master/docs/VALIDATION.md)
- [reims-vgpu](https://github.com/steelbrain/reims-vgpu)；[MoltenVK](https://github.com/KhronosGroup/MoltenVK)
- [touchHLE](https://github.com/touchHLE/touchHLE/blob/trunk/README.md)
- [Skia 文本说明](https://skia.org/docs/user/tips/)；[libkqueue](https://github.com/mheily/libkqueue)
- [Foundation 项目边界](https://github.com/swiftlang/swift-corelibs-foundation/blob/main/README.md)；[URLSession 实现](https://github.com/swiftlang/swift-corelibs-foundation/blob/main/Sources/FoundationNetworking/URLSession/URLSession.swift)
- [OpenSwiftUI](https://github.com/OpenSwiftUIProject/OpenSwiftUI/blob/main/README.md)；[SkipUI](https://github.com/skiptools/skip-ui)
