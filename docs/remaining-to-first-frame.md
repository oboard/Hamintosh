# 原版 SwiftUI 首帧：当前缺口与并行边界

核对日期：2026-10-26。依据 `docs/v1.md`、当前源码和真机报告。
本文件是实施拆分，不表示以下工作已经完成。

2026-10-26 进展更新：
- `__ulock_wait/__ulock_wake` 已实现真实跨线程阻塞（`runtime/src/darwin/ulock.rs`，
  7 项 Rust 测试）。真机运行行为随之改变：App 进程存活、诊断报告不再返回，
  因为主线程真实地阻塞在 RunningBoard handshake 的 dispatch_sync 等待上
  （`artifacts/incomplete-run.json`）。这不是回归，是前置条件已就位、
  缺 worker 线程的直接证据。
- bsdthread_register 的入口与偏移已记录进 Process 状态。
- 从缓存 libsystem_pthread 反汇编得到 workqueue 线程用户态 ABI：
  `_start_wqthread` 直接进入 `__pthread_wqthread(x0=pthread 结构,
  x2=stacklowaddr, x3=eventlist, x4=upcall_flags, x5=nevents)`；flags bit22 为 workloop
  路径，bit19 为 kevent 路径；workloop ID 在 eventlist 前 8 字节。返回时分别用 workq_kernreturn
  WQOPS_THREAD_WORKLOOP_RETURN(0x100)/THREAD_RETURN(0x4) 停驻。
  这定义了 native worker 引导必须布置的寄存器与栈。
- 线 2/3/4 首批成果已入库：RunningBoard 信封识别与域名错误回复
  （`docs/scene-ipc-protocol.md`）、CoreAnimation 提交路径结论
  （`docs/apple-rendering.md`：全场景提交走 render server Mach IPC；
  单层 CPU 光栅化可经 CABackingStore；IOSurface 依赖未模拟的 IOKit trap；
  暂存 sysroot 缺物理字体）、帧来源诊断与重复运行验收脚本
  （`docs/host-presentation.md`）。

2026-10-27 调度推进：
- 已移除空 pthread、虚构事件的同步启动代码。现在预建 4 个宿主 worker，
  为每个 worker 分配双侧保护页、独立 guest 栈和 pthread/TSD 区。
- bsdthread_register 从实际的 60 字节 packed 结构读取 TSD 偏移（真机为
  224），校验 pthread 尺寸、槽位边界和重复注册，不再读取无定义的 x6。
- TSD、thread ID、Mach thread self、special reply port 和信号屏蔽字按宿主
  线程隔离；保持宿主自己的 TLS。
- 32 槽请求存储保留完整 kevent、QoS 和 debounce 信息；处理删除、重复更新、
  ESTALE 及容量耗尽，并以 lease 防止同一 workloop 同时交付两个 worker。
- 以执行门串行运行 guest/pager，在事件注册返回及真实 ulock 阻塞时让出执行权。
  workq_kernreturn 非返回停驻；关闭以 EINTR 取消等待，不伪造成功唤醒。
- 仅在 native 调度器安装后声明 WORKLOOP 能力。真机确认未声明该位时，
  libdispatch 留下空 workloop 回调；声明后已真正调用原版 libdispatch。
- `artifacts/worker-enabled-run/device-compat-report.json` 记录一个 worker
  `calls=1 parks=1`：真实事件已执行到正常停驻。另一个 worker 在 Mach trap -40
  （端口 limits 属性查询）停止。
- 随后已补充接收端口的真实 queue limit 状态与 -40 查询。最新
  `artifacts/worker-port-limits-run/device-compat-report.json` 显示同一 worker
  `calls=2 parks=1`，-40 返回 0，第二次执行推进到同步 Mach 消息 3218。
  下一步保留 worker 的完整请求体、核对对应 MIG 协议并补 IPC；目前 worker
  报告含原始寄存器与调用栈，尚未输出该请求体。帧计数为 0，无首帧验收。
- 本轮本地验证：147 项 Rust 测试通过、1 项本机 capture 测试忽略；48 项 Python
  测试通过，Clippy（warnings as errors）及签名 HAP 构建通过。

2026-10-27 普通 worker、端口协议与资源推进：
- 已按实际请求补 MIG 3218（`mach_port_set_attributes`），端口 queue limit
  在设置与查询之间共享真实状态；补 -25 析构、send/dead-name 引用和端口代际。
  代际保留低两位，以兼容 Apple ulock/dispatch 对 thread port name 的编码。
- `__ulock_wait2`（544）使用与 515/516 相同的真实等待表，保留 64 位纳秒超时、
  mach absolute deadline 和 EINTR 关闭语义。真机越过了此前的 ENOSYS 停止点。
- 普通 root queue 请求（WQOPS_QUEUE_REQTHREADS）按真实 count/QoS 入队，
  经原版 `_start_wqthread` 进入 libdispatch，nevents=0 并清除 workloop 标志。
  不使用空事件冒充 workloop 交付；两种回调均复用原线程 TSD。
- 普通 worker 首次进入未选入的 EmojiFoundation RX 页；已将这个原始映像
  纳入签名 cache ELF。随后取得 CoreEmoji 物理 bundle 缺失的真实断言。
- 新增 `tools/stage_system_resources.py`，可暂存指定 Apple 资源并记录源系统版本、
  文件大小与 SHA-256；拒绝 Mach-O/ELF、符号链接和越界路径，不改资源字节。
  当前 CoreEmoji 的 16 个资源（982120 字节）来自本机 Apple iOS 27.0 Simulator
  24A434；设备 cache 仍为 iOS 27.0 24A437。此数据来源差异是已记录的临时限制，
  不表示设备版完整 sysroot 已经补齐；可执行代码没有换成模拟器版本。
- `artifacts/worker-audit-run/device-compat-report.json` 中 42 次 worker 调用全部
  正常停驻（普通 root callback 34 次）；App entry 已执行，正常主运行到诊断上限。
  随后的独立 scene 探针得到非空 FBSScene/connectionOptions，在 stage 24 抛
  NSException，UIScene/window 和帧计数仍为 0。这不能证明正常 scene 生命周期完成。
- 前一轮 `artifacts/coreemoji-resources-run/` 出现 libdispatch 的
  `Release of a queue with corrupt state` 检查；一次成功的 worker 停驻批次不能
  消除该稳定性问题。新增首个 worker 故障标记、完整 callee 寄存器、事件交付与
  deferred changelist 历史，以区分原始故障与停止传播，继续按实际记录修复。
- 已对同一安装版本再次强制停止、重启（`artifacts/worker-audit-repeat/`）。
  两轮均到达主线程 trap 上限和 scene 探针 stage 24 的同一 NSException；
  第二轮 worker 的未完成调用发生在主线程诊断结束后的关闭传播中，
  primaryFault 标记均为 0。两轮仍无 window 和 Apple 帧；下一步取得异常的
  name/reason 并打通正常 FrontBoard scene 交付，不能把探针当正常启动。
- 本地验证：156 项 Rust 测试通过、1 项本机 capture 测试忽略；49 项 Python
  测试通过，Clippy（warnings as errors）和包含资源的签名 HAP 构建通过。

2026-10-27 workloop 同步与 scene 参数修正：
- worker 历史证明普通回调在 NOTE_WL_SYNC_WAIT 后立即继续、释放队列，另一
  worker 随后接收该队列并触发 libdispatch corrupt-state 检查。现已实现按
  workloop/ident 隔离的真实 sync wait、预置 wake、删除唤醒、EXDEV 检查和
  EINTR 关闭；等待期间让出 guest 执行门，并在重新进入前释放宿主互斥锁。
- 修正 kevent receipt 计数与输出容量：复制出的成功/错误回执返回实际数量。
  XNU 不支持的阻塞注册布局和未知 workloop 命令不再直接返回成功。
- 通过保留 Foundation 原预处理器的异常观察器取得实际原因：
  `_UISceneConnectionOptionsContext` 不支持 `_fbsScene`。这属于 scene 探针
  传参错误，不能据此声称缺少 UIKit 功能或正常 App 生命周期已到这个阶段。
- 原始 UIKit 调用点 0x1849761e4..1f4 表明 0x184975334 是无 SEL 参数的
  direct initializer：x0=self、x1=context、x2=FBSScene、x3=specification。
  探针现调用原始构造代码产生 UISceneConnectionOptions，再交给 scene factory。
- `artifacts/scene-options-run/` 已越过该类型异常，推进到实际 Mach 请求：
  -47、message ID 2884、send size 212、destination 0x2103。UIScene/window
  和 Apple 帧仍为 0；需要核对该请求的 IOKit/BackBoard 语义并完成正常 scene 交付。
- 159 项 Rust 测试与 Clippy 通过。原 App、cache 和 PAC 没有为上述修正改写。
  异常观察器只在独立探针 stage 24 注册，链回原处理器并恢复注册状态。

原始 App 主线程现已在正常启动期间与 worker 交错执行，而非仅在故障后的 scene
诊断里启动 worker。完整 workloop owner/sync 协议、Mach 事件投递和线程复用稳定性
仍需按后续真机执行补齐；35 秒诊断 watchdog 与 trap 上限仍是诊断边界。

验收仍是原始 SwiftUIHelloWorld.ipa 在 HarmonyOS ARM64 真机运行，
由 Apple 原版 SwiftUI 生成界面，取得可重复启动、真机截图和诊断证据。
保留 App 代码、签名 ELF AOT 与 PAC；宿主只承载显示与平台兼容。

## 已经证明的边界

| 环节 | 当前证据 | 证据不能证明什么 |
| --- | --- | --- |
| App 输入 | 已核对原 IPA 与暂存 App 可执行文件 SHA-256 一致 | 不能证明全部运行时依赖都已兼容 |
| 可执行映射 | Mach-O/cache AOT 进入签名 ELF；独立 ObjC trampoline 原字节、权限校验通过 | 不能证明后续所有动态加载路径都已覆盖 |
| Apple 启动链 | 原版 dyld 转交原始 App，`appExecuted=true` | 不能等同应用正常运行或渲染成功 |
| Swift/ObjC/PAC | 真机跨越现有 ABI 边界，真实 SwiftUI 回调产生非空 scene configuration | 不能证明所有尚未执行路径的 ABI 与 PAC 都正确 |
| UIKit scene | 独立探针中的 UIApplication、session、configuration、FBSScene、connectionOptions 非空 | 正常 scene 生命周期、UIScene/window 和帧仍未证明 |
| 宿主显示 | 有 XComponent/NativeWindow attach 和 BGRA 提交代码 | 尚未收到 Apple 框架生成的帧 |

10-26 的主运行达到诊断 trap 上限；随后另行执行的 scene 诊断停在
RunningBoard 同步 dispatch 等待。10-27 起已在正常主运行期间交付 worker 事件，
新停止点见上方更新。故障后的 scene 诊断仍不能代替正常 scene 启动流程。
尚未获得正常窗口与 Apple 首帧的证据。

## 必须补齐的工作

### A. Guest 线程、调度和同步

负责文件：`runtime/src/darwin.rs`、`runtime/src/darwin/kevent.rs`、
`native/platform/execution_probe.cpp`、`native/abi/guest_stack.S`。

- 保存并校验 bsdthread 注册的原版线程入口与 pthread/TSD 布局。
- 建立独立 guest 栈、线程身份、TSD、PAC 认证后的原版工作线程入口。
- 实现 workloop 请求登记、队列状态 debounce、QoS、事件交付与工作线程返回。
- 已补充真实 ulock wait/wake、wait2 和按注册 ABI 引导的 Apple worker；
  继续核对完整 workloop ownership/sync、重复交付和普通队列回调的稳定性。
- 处理线程停放、重用、嵌套等待及 signal/trap 状态恢复。
- 将一次性诊断执行整理成可持续运行的 guest 调度；诊断 trap 上限不得成为正常生命周期。

最新原始事件记录有 21 条 change、10 次 NOTE_WL_THREAD_REQUEST，丢弃 0 条。
这些请求出现在主运行阶段；scene 等待可能依赖此前已入队但未执行的工作。
还存在 SYNC_WAIT/SYNC_WAKE 控制，不能只实现普通 WQOPS_REQTHREADS。
Apple libdispatch 工作线程源码在 nevents=0 时直接返回，因此不能用空事件启动
workloop worker 来冒充真正交付。

完成证据：原版 Apple worker 实际执行已登记队列、产生真实等待条件变化，
当前同步等待能正常继续，且保持原 App 与主线程 TSD 正确。

### B. 正常 scene 生命周期与系统服务

负责文件：`runtime/src/darwin/ipc.rs`、`xpc.rs`、`ports.rs`、`display.rs`；
scene 诊断位于 `native/platform/execution_probe.cpp`。

- 根据实际请求补 RunningBoard/FrontBoard 等本地服务所需协议与对象身份。
- 打通 FBSScene、连接参数、settings、context binder、UIScene delegate 生命周期。
- 将已经验证的 scene 建立逻辑纳入正常启动路径，避免依赖故障后的诊断调用。
- 按实际等待需求补 Mach 消息交付和事件源，不把所有服务统一回复成功。

现有 BackBoard 主屏几何回复只是一个已观测协议，不是完整窗口服务。
调度修复后是否还需要哪些服务请求，以实际执行为准。

完成证据：正常 App 启动产生 UIWindowScene、UIWindow、root view/controller，
窗口尺寸与屏幕一致，生命周期回调顺序有效。

### C. Apple 图形生产端（最大未验证项）

现有 `native/graphics/harmony_surface.cpp` 只承接已有 BGRA 像素。
当前没有证据证明 CoreAnimation 能在本环境产出这些像素。

- 查明当前 Apple CoreAnimation 的 transaction/context、渲染服务和提交边界。
- 优先验证 v1.md 的 CPU 路线：Apple 实际图层内容 → IOSurface/CPU BGRA。
- 核实软件渲染入口、字体/图片/文本依赖、IOSurface 内存和相关系统调用。
- 若实际执行强依赖 GPU/外部 compositor，记录具体证据并评估所需兼容接口；
  不预先宣称 CPU 路线已可用，也不直接扩张为完整 Metal 实现。

可提前做与 scene 无关的最小 Apple 图层/文本渲染验证，但只证明图形边界；
最终仍必须连接原 App 的真实 layer tree。

完成证据：原 App SwiftUI 布局生成真实图层，Apple 渲染路径产生可读像素，
像素包含 App 内容并能追溯到该次 transaction。

### D. 宿主呈现与持续更新

负责文件：`native/graphics/`、`harmonios/src/main/cpp/napi_init.cpp`、
`harmonios/src/main/ets/pages/Index.ets`。

- 把真实 Apple framebuffer 接入已有 BGRA 提交接口。
- 核对 stride、像素格式、尺寸/scale、NativeWindow buffer 生命周期与 fence。
- 接入帧提交时机、surface 重建、前后台恢复和资源释放。
- 若需触摸触发状态更新，再补坐标变换和 UIKit 输入投递；不阻塞静态首帧验证。

可用测试像素独立验证宿主提交接口，但不得计为 SwiftUI 首帧。

完成证据：同一次 Apple transaction 的帧实际显示在 XComponent，
真机截图与帧诊断对应，重新启动后仍能显示。

### E. 端到端验收与运行稳定性

- 原始 IPA/可执行代码一致性、AOT 段权限及 PAC 保留证据。
- 正常启动诊断依次记录 App entry、scene/window、layer、Apple frame、host present。
- 冷启动/强制停止后重复运行，保存每次结果、截图与帧来源。
- 核对异常、重复启动和 surface 重建不会使用上次残留窗口或帧。
- 后续按原要求整理独立运行时 UIAbility；首帧关键路径前不做启动器视觉改版。

## 可并行推进的四条线

| 工作线 | 可立即独立做的事 | 合流依赖 |
| --- | --- | --- |
| 1：线程与同步 | workloop/ulock/guest worker、TSD 和停放恢复 | 是当前 scene 等待的前置条件 |
| 2：scene/IPC | 静态分析协议、梳理对象/回调契约、服务处理器与协议测试 | 活的 scene 全流程验证需要线 1 |
| 3：Apple 渲染 | 探索真实 CA 软件渲染、IOSurface 和文本依赖，独立最小验证 | App 图层合流需要线 2 |
| 4：宿主呈现/验收 | BGRA 提交真机验证、帧诊断、截图及重复启动脚本 | 最终内容合流需要线 3 |

调度与 scene 线都可能修改 execution_probe.cpp；若拆给不同执行者，应指定单一
集成负责人，先约定接口并避免同时编辑该文件。设备上的安装/启动/日志采集应串行，
防止互相强制停止或覆盖报告。离线源码分析、独立模块实现与测试可以并行。

推荐顺序：线 1 优先解除当前等待，同时尽早启动线 3 验证图形路线；
线 2 做协议准备，线 4 做宿主与验收准备。不要等窗口出现后才开始研究 CA 输出。

不以百分比或剩余小时估算完成度：scene 服务与 Apple 图形生产端仍存在未执行路径。
下一组可核验里程碑是：真实 worker 执行 → 正常 window 非空 → Apple 像素产生 →
真机显示 → 重复启动与截图验收。

本机证据：`artifacts/device-compat-report.json`、
`artifacts/scene-bringup-evidence/workloop-requests.json`、
`artifacts/build-workloop-changes.log`、`artifacts/run-workloop-changes-installed.log`。
解码工具：`python3 tools/analyze_workqueue_report.py artifacts/device-compat-report.json`。
