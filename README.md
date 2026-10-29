
# 果易通

**Harmonios**

> 在 HarmonyOS 设备上原生执行 ARM64 iOS 应用的通用 AOT 兼容层与运行时架构。

架构见 [v1 方案](docs/v1.md)。当前已打通 ArkUI → C++ → Rust、真机 Gate 0、Mach-O 签名 ELF 打包和原版 iOS dyld 引导，并持续补齐 MIG、XPC、Swift ABI 与图形输出。

**最新进展（2026-10-28）：**
- **宿主全屏表面已验证**：已有蓝色地球和 Hello World 测试画面来自宿主绘制，不能作为原版 SwiftUI 首帧证据。自动提交固定画面的路径已停用；显式宿主演示使用 `test-pixels` 来源。
- **统一 Rust 工具链**：`harmonios` 负责 IPA 准备、AOT/缓存打包、签名构建、真机部署和报告采集。新 Gallery IPA 已进入 App 代码，仍在完善 ARM64/ARM64e ABI 边界。工具命令和迁移验证见 [工具链](docs/toolchain.md)。
- **Specified 独立实例启动模式**：基于 `AbilityStage` 与 `SpecifiedAbility` 架构，实现任意 iOS App 独立窗口生命周期管理，主窗口全屏沉浸式无边框接管，支持系统原生侧滑全局返回手势。
- **IPA 动态图标与元数据自适应解析**：`tools/converter` CLI 自动解析 `Info.plist` 与 IPA 内置资产，支持 Apple 专有 CgBI 优化 PNG 自动规整解码与实时展示，精准呈现 `版本号 · Bundle ID · 体积` 标准描述。
- **OpenHarmony 标准 uiMaterial 沉浸式桌面**：
  - 全英文界面（English UI）与暗色材质自适应。
  - 纯色高反差 Apple 经典圆角矩形安装按钮（`#0A84FF`）。
  - 双项悬浮胶囊圆角毛玻璃导航栏（`｜🏠 Home ｜ ⚙️ Settings｜`，28vp 药丸造型，`BlurStyle.Thin` 实时背板高斯模糊）。

---

## 架构体系与核心模块

### 1. 转换与编译工具链 (`tools/converter/`)
提供现代化的 macOS / Linux CLI 工具：
- `harmonios inspect <Foo.ipa>`：深层解包分析 Mach-O 头表、段分布、ARM64/ARM64e 依赖库树、动态符号表及应用资产。
- `harmonios convert <Foo.ipa>`：自动生成针对 HarmonyOS 的统一 AOT 镜像、C ABI 包装层、规整化应用图标与 `manifest.json` 清单。
- `harmonios build` / `sign` / `install`：联动 DevEco 工具链完成 HAP 组装、证书签名与真机一键推送部署。

### 2. 运行时兼容内核 (`runtime/`)
用 Rust 实现的高性能、内存安全的 Darwin/XNU 内核兼容层：
- **模块化 MIG 子系统 (`runtime/src/mig/`)**：基于 `MigRegistry` 动态路由，解耦 `task`、`vm`、`port`、`host`、`iokit`、`clock` 等核心子系统，实现严格的 Mach 消息结构体与 NDR 编解码规范。
- **系统服务总线 (`runtime/src/services/`)**：提供即插即用的 `SystemService` 框架与 `BootstrapNamespace` 命名空间管理，内置 `cfprefsd`、`notification_center`、`runningboard` 核心服务，支撑 Foundation / UIKit 上层调用。
- **BSD & XNU Syscall 调度**：支持 TSD 基址直接分发（hot-path 规避）、POSIX 文件虚拟化、内存安全映射与原子事件驱动。

### 3. 平台胶水与执行探针 (`native/`)
- **ARM64e PAC 认证体系**：在 `native/abi/pac_sign.S` 中实现 IA/IB/DA/DB 硬件密钥指针重签名与认证。
- **直接调用桩 (`native/abi/direct_call_stub.S`)**：消除陷阱热路径，通过稳定 C ABI 提升系统调用吞吐量。
- **原生图形表面桥接 (`native/graphics/`)**：封装 `OHNativeWindow` 与 `libnative_drawing` 2D 矢量引擎，桥接 CoreAnimation / IOSurface 软件呈现流水线。

### 4. ArkUI 宿主启动器 (`harmonios/`)
- **Applications 动态应用桌面**：动态扫描沙箱与已安装 Feature，展示真实应用图标、名称与规格。
- **AppRunner 独占全屏容器**：作为 `HarmoniosSpecifiedAbility` 的承载容器，实现无外框、无干扰的沉浸式应用呈现。

---

## AOT 与 PAC 的边界

当前 AOT 指将原始 Mach-O 段及选中的共享缓存代码封装到 HAP 签名 ELF，
由 ARM64 CPU 原生执行；它尚不是把 ARM64e 全量重编译成 ARM64 的编译器。
现有代码页转换处理 Darwin SVC 和线程指针访问，不全局删除 PAC/AUT 或认证跳转。
缓存中的认证指针按实际装载地址和当前进程密钥重建。

目标 IPA 是 ARM64，而 iOS 共享缓存是 ARM64e，因此仍需在两者的 ABI 边界适配。
适配须限定到已审计的指令、字段与缓存 UUID；ARM64e 返回的已签名指针必须先验证
原有签名，再提供给 ARM64 调用方使用，不得直接剥离签名来接受认证失败的指针。

---

## 构建与真机验证

需要 DevEco Studio 的 SDK、Node、Java、hvigor/HDC、Rust；远程下载使用 curl。生产构建和真机运行不再依赖 Python。
本机签名沿用 DevEco 的 `build-profile.json5`，不要提交私有签名材料。

```sh
# 1. 运行 Runtime 单元测试与转换器测试
cargo test --manifest-path runtime/Cargo.toml
cargo test --manifest-path tools/converter/Cargo.toml
cargo clippy --manifest-path tools/converter/Cargo.toml --all-targets -- -D warnings

# 2. 转换目标 IPA
cargo install --path tools/converter --locked
harmonios prepare-ipa /path/to/Foo.ipa

# 3. 组装与真机一键调试
harmonios run-device --no-clean --output artifacts/my-run
```

`harmonios run-device` 会在选页配置更新或缓存不存在时重打包，并在缺少数据包时生成非执行数据 pack。
可执行 cache 由独立签名的 `ioscache` HSP 提供，entry HAP 不再携带该库。
工具自动暂存预编译库、构建 HSP；首次将 HAP/HSP 一起安装，后续按 SHA-256
stamp 和已安装模块状态复用 HSP，仅上传小 HAP。

---

## 项目组织架构

- `include/harmonios/runtime.h`：统一 C ABI 接口规范，定义运行时上下文、应用描述符与系统调度入口。
- `runtime/`：Rust 编写的 Darwin/XNU 兼容内核，包含 MIG 接口、系统服务与内存虚拟化。
- `native/`：C++ / 汇编平台层，包含 PAC 签名桩、直接系统调用桩、`OHNativeWindow` 图形管线与探针。
- `harmonios/`：ArkUI 宿主工程，包含 Applications 桌面、Specified 独立实例启动器与暗黑材质组件。
- `tools/converter/`：独立 Rust CLI 转码工具，实现 IPA 解包、Mach-O 深度分析、AOT 重写与资源导出。
- `tools/`：HSP 打包缓存提取、真机自动化测试与故障分析工具链。
- `docs/`：包含 v1 架构规约、CoreAnimation 渲染流水线、MIG 通信协议与启动记录。
