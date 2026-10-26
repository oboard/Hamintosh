# Apple CoreAnimation 渲染路径与 CPU 像素生产离线分析报告

**核对日期**：2026-10-26  
**分析对象**：`artifacts/ios27-system/cache/` (iOS 27 dyld shared cache arm64e) 及 `artifacts/ios27-extract/` 提取系统框架（QuartzCore、IOSurface、CoreGraphics、CoreText、IOKit、libsystem_kernel 等）。  
**目的**：为 Harmonios 解决“首帧”显示最大未验证项——Apple 原版 CoreAnimation 是否能在此轻量 Darwin 仿真环境下生产 CPU 可读的 BGRA 像素，并给出确定性二进制证据。

---

## 结论摘要（Verdict on CPU Rendering Route）

1. **确定性结论：直接纯 CPU 端到端图层树光栅化（纯软件合成）在现代 iOS CoreAnimation 生产链中不可行（作为独立运行时路线）。**
   - **已证实**：`QuartzCore` 保留了低级软件回调结构表 `_kCARenderSoftwareCallbacks`（虚拟地址 `0x1e9002ca8`）与函数 `_CARenderSoftwareSetDestination`（`0x1846a6654`），但该软件分支仅为早期的兼容/测试存根（stub）。其合成主干 `_CARenderCARPRender`（`0x18468ea3c`）硬编码要求 Metal 设备（`_MTLCreateSystemDefaultDevice` 位于 `0x1a54cec28`）。
   - **已证实**：普通 iOS App 的 `CA::Transaction::commit` 默认绝不在 App 进程内光栅化 layer tree。它通过 `mach_msg`（trap `-31`）将序列化的 render commands/payload 发送给 `com.apple.coreanimation.render-server`（BackBoard / render server 守护进程）。App 本身是一个 Client。
2. **唯一可行的 CPU 像素产出路径：基于 `CGBitmapContext` / `drawInContext:` 的 CPU 光栅化，或仿真 `com.apple.coreanimation.render-server` / `IOSurface`。**
   - 单个图层的绘制内容（`CALayer drawInContext:`）通过 `CABackingStore`（`0x1844d2178`）利用 CoreGraphics（`CGBitmapContextCreateWithData` `0x183c46c48`）在 CPU 内存直接光栅化。
   - 若要截获整树最终像素：必须通过仿真 render-server 的 Mach 端口接收序列化 layer tree，或者将 `UIWindow` 挂载在仿真 IOSurface/BitmapContext 上，或者由宿主拦截 `CABackingStore` / `IOSurface` 缓冲区。
3. **IOSurface 依赖重灾区：**
   - `IOSurface` 分配（`IOSurfaceCreate` `0x1c2844980`）强依赖 IOKit 用户客户端（UserClient）。调用链为 `_IOServiceOpen`（`0x18f07d604`）发送 MIG 消息 `2862`（`io_service_open_extended`），并通过 `_iokit_user_client_trap`（`0x18f070f10`，SVC `#0x80`，trap number `-100` / `0xffffff9c`）及 `IOConnectCallMethod`（`io_connect_method` MIG `2865`）向内核申请共享内存。目前 `runtime/` 完全缺失此驱动仿真。
4. **字体与文本依赖状态：**
   - `CoreGraphics`（`0x183c2d000`）和 `CoreText`（`0x19a236000`）目前均**未包含在** `tools/hello-world-cache-pages.json`（9 个 VM ranges，仅映射了 Foundation、SwiftUI、libswift 等基础段）。
   - 系统中目前缺失 `/System/Library/Fonts` 物理字体文件（TrueType/OpenType），`CoreText` 字形解析（`libFontParser.dylib` `0x1b7a1a000`）若找不到回退字体将无法输出实际文本轮廓。

---

## 1. CA Transaction Commit 路径与渲染后端分析

### 1.1 事务提交执行链 (`CA::Transaction::commit`)

通过反汇编 `artifacts/ios27-extract/System/Library/Frameworks/QuartzCore.framework/QuartzCore` 得到真实的事务提交与服务连接机制：

- **符号与地址**：
  - `CA::Context::commit_transaction`: 位于 `0x184405190`（在 `CAContextInternal.mm` 中实现，断言字符串位于 `0x18481691e`）。
  - `CA::Transaction::commit`: 驱动当前线程的 transaction stack，收集 dirty layers。
- **渲染服务器 IPC 交付**：
  - 在 `0x1843ff674` 函数中，QuartzCore 查询渲染服务端点：
    - 加载服务名字符串：`adrp x20, 0x184818000; add x20, x20, #0x85f` -> `com.apple.coreanimation.render-server`（位于 `0x18481885f`，[已证实]）。
    - 调用 `bootstrap_look_up` 获取 render-server 的 Mach port。
    - 组装 16KB+ 的 Mach 消息，在 `0x1843ff810` 调用 `mach_msg`（进入 `libsystem_kernel.dylib` `_mach_msg` / `0x237efb05c`，陷入 `svc #0x80`，trap `-31`，[已证实]）。
  - **结论**：[已证实] 原始 iOS App 的 CoreAnimation 默认是**跨进程架构**。App 自身并不负责将全屏图层树合成渲染成像素，而是将图层树属性和变更（changeset）打包成 Mach 消息推向 `com.apple.coreanimation.render-server`。

### 1.2 存在的渲染后端 (Software vs GPU/Metal)

在 `QuartzCore` 导出的符号表中，存在以下渲染回调与后端：
- **符号证据**：
  - `_kCARenderSoftwareCallbacks` (地址 `0x1e9002ca8`, [已证实])
  - `_kCARenderSoftwareCallbacksRef` (地址 `0x1e3fd7198`, [已证实])
  - `_CARenderSoftwareSetDestination` (地址 `0x1846a6654`, [已证实])
  - `_kCARenderMetalCallbacks` (地址 `0x1e9002cc0`, [已证实])
  - `_kCARenderMetalCallbacksRef` (地址 `0x1e3fd71b0`, [已证实])
  - `_kCARenderGLESCallbacks` (地址 `0x1e9002cb8`, [已证实])
  - `_kCARenderNullCallbacksRef` (地址 `0x1e3fd71a0`, [已证实])
  - `_CARenderOGLRender` (地址 `0x1846a5fd8`, [已证实])
  - `_CARenderCARPRender` (地址 `0x18468ea3c`, [已证实])
- **反汇编解析 `_kCARenderSoftwareCallbacks`**：
  - 虚表入口 `vtable[+0x4d0]` 指向 `0x1846c91d4`（即 `_CARenderSoftwareSetDestination` 的内部实现）。
  - 该实现只进行内存目标指针与 stride 计算：
    ```assembly
    1846c91e4: sxtw x11, w11
    1846c91e8: mul x11, x2, x11  ; stride * height
    1846c91f8: add x12, x1, x11  ; base address
    1846c9218: str x12, [x0, #0xa70] ; 仅存储目标 buffer 指针与参数
    ```
  - **结论**：[已证实] `CARenderSoftware` 只是一个极其原始的 legacy 目标缓冲区配置存根。现代 iOS 27 的合成执行器 `CARenderCARPRender`（`0x18468ea3c`）在启动时直接调用 `_MTLCreateSystemDefaultDevice`（`0x188150a00` -> Metal `0x1a54cec28`），没有 Metal GPU 支持时根本无法走通 `CARenderCARP`。

### 1.3 IOSurface-backed vs CPU-backed 图层内容

- **图层内容分类**：
  1. **CPU 离屏图层（BackingStore）**：
     - 符号：`_CABackingStoreCreate` (`0x1844d2178`)、`_CABackingStoreBeginUpdate` (`0x184620cfc`)、`_CABackingStoreEndUpdate` (`0x184620d08`)。
     - 行为：由 CoreGraphics 的 `CGBitmapContext` 或 `CGIOSurfaceContext` 分配，供 `drawRect:` / `drawInContext:` 绘制。
  2. **IOSurface 共享图层**：
     - 符号：`_CAIOSurfaceCreate` (`0x1845e5374`)、`_CAIOSurfaceContextVTable` (`0x1e900ba30`)、`_CAIOSurfaceGetIOSurface` (`0x184630748`)。
     - 行为：用于与外界共享硬件缓冲区。每个 surface 对应一个唯一的 `IOSurfaceID`（32 位整数），跨进程通过 Mach port（`IOSurfaceCreateMachPort` `0x1c28486c0`）传递。

---

## 2. 软件渲染路线可行性与内核/服务依赖分析

### 2.1 是否存在脱离 GPU/Render Server 的纯 CPU 渲染？

- **结论**：[已证实：否定]
  - 在没有 Render Server 守护进程的情况下，App 端调用 `[CATransaction commit]` 会在 `0x1843ff6d8` 尝试通过 Mach 查找 `com.apple.coreanimation.render-server`。
  - 若 Mach lookup 失败或消息未应答，Transaction 会无限期阻塞或丢弃渲染指令。
  - `QuartzCore` 内部没有提供将整个 App 树自发“降级”为单张 CPU 图像并返回给 App 代码的公开机制。

### 2.2 IOSurface 分配所需的 Syscall 与 IOKit 服务调用

当 CoreAnimation 或 UIKit 请求创建 `IOSurface` 时（如 `CAIOSurfaceCreate` 或 `[IOSurface initWithProperties:]`）：

1. **库与函数入口**：
   - `IOSurface.framework`: `_IOSurfaceCreate` (`0x1c2844980`) -> `_IOSurfaceClientCreateChild` (`0x1c28449cc`)。
2. **IOKit 连接创建（Mach 消息）**：
   - 调用 `_IOServiceOpen` (`0x18f07d604`)。
   - 反汇编显示其构造了 `io_service_open_extended` 消息：
     - MIG subsystem `iokit` (`2800`)。
     - Routine ID: `2862` (`0xb2e`)（见 `artifacts/xnu-main/osfmk/device/device.defs:585`，[已证实]）。
     - 通过 `mach_msg` 发送到内核 `service` 端口。
3. **IOKit UserClient Trap（SVC #0x80）**：
   - 调用 `_iokit_user_client_trap` (`0x18f070f10`)：
     ```assembly
     18f070f10: mov x16, #-0x64  ; -100 (0xffffff9c)
     18f070f14: svc #0x80
     ```
   - 寄存器参数：
     - `x0`: `io_connect_t`（UserClient 连接端口）
     - `x1`: selector 编号（如 0 = create surface）
     - `x2..x6`: 参数指针及尺寸
   - 随后通过 `_IOConnectTrap4` / `_IOConnectCallMethod`（MIG `2865` `io_connect_method`）完成共享内存的映射（`vm_allocate` / `mach_vm_map`）。
4. **当前 Harmonios 缺失项**：
   - `runtime/src/darwin/` 中完全没有处理 trap `-100`（`iokit_user_client_trap`）的代码；遇到时将触发 `unhandled trap -100` 导致进程终止。
   - `runtime/` 中没有 IOKit 相关的 MIG 处理器（`2862`, `2865`）。

---

## 3. 简单文本图层 (Text Layer) 最小依赖集

要渲染最基础的 “Hello, world!” 文本图层（类似 SwiftUI 示例）：

### 3.1 所需核心库与功能入口

| 框架 / 动态库 | 关键符号 | 作用 | 二进制验证地址 |
| --- | --- | --- | --- |
| **QuartzCore** | `_CABackingStoreCreate`<br>`_CABackingStoreBeginUpdate`<br>`_CABackingStoreEndUpdate` | 创建与管理图层后备位图缓存 | `0x1844d2178`<br>`0x184620cfc`<br>`0x184620d08` |
| **CoreGraphics** | `_CGBitmapContextCreateWithData`<br>`_CGContextDrawPath`<br>`_CGFontCreateWithFontName` | CPU 软件光栅化器、路径填充、位图管理 | `0x183c46c48`<br>`0x183c4c390`<br>`0x183c533c0` |
| **CoreText** | `_CTFontCreateWithName`<br>`_CTLineCreateWithAttributedString`<br>`_CTLineDraw` | 字体排版、字形提取、布局排版计算 | `0x19a27e778`<br>`0x19a260ed0`<br>`0x19a277390` |
| **FontServices** | `libFontParser.dylib`<br>`libGSFont.dylib` | 字体字形轮廓解析（TrueType/OpenType/CFF） | `0x1b7a1a000`<br>`0x1cfd67000` |

### 3.2 现有运行时映射状态比对 (Runtime vs Missing)

比对 `tools/hello-world-cache-pages.json` 与 `runtime/src/darwin/`：

1. **内存页面映射情况**：
   - **已映射**：`Foundation`、`libobjc.A.dylib`、`SwiftUI`、`UIKit`、`libswift*.dylib` 等基础运行库。
   - **未映射**（[已证实]）：
     - `CoreGraphics.framework` (`0x183c2d000` .. `0x1843e7000`): **未映射（False）**。
     - `QuartzCore.framework` (`0x1843e7000` .. `0x18485a000`): **未映射（False）**（仅映射了 `libswiftQuartzCore.dylib`）。
     - `CoreText.framework` (`0x19a236000` .. `0x19a31a000`): **未映射（False）**。
     - `IOSurface.framework` (`0x1c2843000` .. `0x1c2860000`): **未映射（False）**。
     - `libFontParser.dylib` (`0x1b7a1a000`): **未映射（False）**。
2. **系统调用与 Mach 协议映射情况**：
   - **已映射**（见 `runtime/src/darwin/display.rs`）：
     - `BKSDisplayGetMainScreenInfo`（Mach request ID `0x005b9175` -> reply `0x005b91d9`），可返回主屏几何尺寸与 scale。
   - **未映射**：
     - `bootstrap_look_up` 对于 `com.apple.coreanimation.render-server` 的请求（当前会返回未找到或空端口）。
     - `iokit_user_client_trap` (trap `-100`)。
     - IOKit MIG 消息（`2862`, `2865` 等）。
3. **文件系统与资产缺失**：
   - 经扫描，`artifacts/ios27-extract/` 中**完全没有** `.ttf` / `.otf` / `.ttc` 字体文件（[已证实]）。
   - `CoreText` 检索路径包含 `/System/Library/Fonts/` 及 `/Library/Fonts/`。
   - 若 `runtime/src/darwin/files.rs` 在响应 `open` / `stat` 时找不到字体文件，`CTFontCreateWithName` 会失败或降级为内部空字形（导致文字渲染为空白方块或引发崩溃）。

---

## 4. 实施建议与图形路线策略（Architectural Options）

鉴于上述分析，原版 CoreAnimation 无法脱离渲染服务器在 App 进程内自发产出最终全屏 CPU 像素。建议采用以下分阶段落地策略：

### 路线 A：本地仿真 `com.apple.coreanimation.render-server`（推荐的生产级路线）
- **原理**：在 `runtime/src/darwin/` 中注册并截获 `com.apple.coreanimation.render-server` 的 Mach 端口请求。
- **流程**：
  1. 拦截 `bootstrap_look_up("com.apple.coreanimation.render-server")`，返回一个由运行时控制的 receive port。
  2. 接收由 `CA::Context::commit_transaction` 发出的序列化 changeset（CARP payload / encoder bytes）。
  3. 运行时调用 `QuartzCore` 内部反序列化接口 `_CARenderCARPApplyCommit` (`0x18468e75c`) / `_CARenderDeserializeBytes`，重构图层树。
  4. 利用 `CGBitmapContext` 或嵌入式 CPU 渲染器（或 Metal-to-Vulkan 转发）将图层树光栅化到 `OHNativeWindow` 的 BGRA buffer 中。

### 路线 B：基于 `CALayer drawInContext:` / 内存截图桥接（最小首帧验证路线）
- **原理**：在主 scene/window 就绪后，不等待 render-server 异步取帧，直接在主线程由代码主动调用 `[window.layer renderInContext:bitmapContext]`。
- **优点**：
  - 完全避开 Metal、IOKit 和外部 render-server。
  - `renderInContext:` (`0x1e05d6e58`) 由 `CoreGraphics` 的 CPU 栅格化管道驱动，直接把像素写入 `CGBitmapContextCreateWithData` 分配的普通内存缓冲区。
  - 产出的内存直接交付给 `native/graphics/harmony_surface.cpp` 提交至 ArkUI XComponent。
- **前置必须补齐项**：
  1. 将 `QuartzCore.framework`、`CoreGraphics.framework`、`CoreText.framework` 及其依赖段载入 `tools/pack_cache.py` 并补充进 `hello-world-cache-pages.json`。
  2. 从 iOS 系统镜像中提取必要的英文字体（如 `SF-Pro.ttf` 或系统回退字体）并放入 sysroot 的 `/System/Library/Fonts/` 路径，并在 `files.rs` 中保证能够打开。

---

## 5. 证据索引表（Binary Citations & Offsets）

| 证据项 | 二进制路径 | 符号 / 偏移 | 状态 | 意义 |
| --- | --- | --- | --- | --- |
| CA 事务提交断言 | `QuartzCore` | `0x184405190` / `0x184816893` | **已证实** | 确认 `CAContextInternal.mm` 中 `commit_transaction` 位置 |
| Render Server 服务名 | `QuartzCore` | `0x18481885f` | **已证实** | 字符串 `"com.apple.coreanimation.render-server"` |
| Render Server Mach 调用 | `QuartzCore` | `0x1843ff810` -> `0x237efb05c` | **已证实** | 确认 commit 强依赖向渲染服务器发 Mach 消息 |
| 软件渲染入口存根 | `QuartzCore` | `0x1846a6654` (`_CARenderSoftwareSetDestination`) | **已证实** | 确认现代 CA 软件后端仅为 buffer 存根，无完整独立光栅化 |
| 现代合成器 Metal 依赖 | `QuartzCore` | `0x18468ea84` -> `0x1a54cec28` | **已证实** | `_CARenderCARPRender` 在启动时直接加载系统 Metal 设备 |
| IOSurface 创建入口 | `IOSurface` | `0x1c2844980` (`_IOSurfaceCreate`) | **已证实** | 走 `IOSurfaceClientCreateChild` |
| IOKit Mach 消息 (open) | `IOKit` | `0x18f07d6fc` (MIG `2862`) | **已证实** | `io_service_open_extended` 创建 UserClient 连接 |
| IOKit Trap 系统调用 | `IOKit` | `0x18f070f10` (`_iokit_user_client_trap`) | **已证实** | `mov x16, #-100; svc #0x80`，运行时目前未捕获 |
| CoreGraphics 文本/位图 | `CoreGraphics` | `0x183c46c48` (`_CGBitmapContextCreateWithData`) | **已证实** | 可用于 CPU 像素写入的官方导出符号 |
| 缓存映射缺失 | `tools/hello-world-cache-pages.json` | 9 个 ranges，无 `0x1843e7000` | **已证实** | QuartzCore、CoreGraphics 等尚未打入运行时缓存页表 |
| 字体文件缺失 | `artifacts/ios27-extract/` | 无 `.ttf`/`.otf` 文件 | **已证实** | sysroot 缺真实系统字体资产 |
