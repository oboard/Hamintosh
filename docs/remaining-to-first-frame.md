# 原版 SwiftUI 首帧：当前缺口与并行边界

核对日期：2026-10-26。依据 `docs/v1.md`、当前源码和真机报告。
本文件是实施拆分，不表示以下工作已经完成。

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
| UIKit scene | `UIApplication`、session、configuration、scene specification 非空 | FBSScene、UIScene、window 仍为空 |
| 宿主显示 | 有 XComponent/NativeWindow attach 和 BGRA 提交代码 | 尚未收到 Apple 框架生成的帧 |

当前主运行会达到诊断 trap 上限；随后另行执行的 scene 诊断停在
RunningBoard 同步 dispatch 等待。该诊断不能代替正常 scene 启动流程。
最新报告仍为 `windowCount=0`，没有首帧。

## 必须补齐的工作

### A. Guest 线程、调度和同步

负责文件：`runtime/src/darwin.rs`、`runtime/src/darwin/kevent.rs`、
`native/platform/execution_probe.cpp`、`native/abi/guest_stack.S`。

- 保存并校验 bsdthread 注册的原版线程入口与 pthread/TSD 布局。
- 建立独立 guest 栈、线程身份、TSD、PAC 认证后的原版工作线程入口。
- 实现 workloop 请求登记、队列状态 debounce、QoS、事件交付与工作线程返回。
- 补充真实 ulock wait/wake；等待值未变、生产者未执行时不得返回假唤醒。
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
