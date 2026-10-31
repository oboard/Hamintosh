# 图形可行性验证记录（2026-10-30）

## 已验证

- 设备 Vulkan 预检：`physicalDevices=1`，`VK_KHR_timeline_semaphore=true`。
- metal2vulkan 固定版本：`219f01365dc4c8eb346816c405b5b17403793764`。
- Mac 对照：MoltenVK + Apple M1 Pro 运行上游 `render_to_texture` fixture，64 个 texel 全部符合预期。
- HarmonyOS 真机：同一 fixture 内嵌到 Rust runtime，在 `Maleoon 920C` 上完成离屏渲染和 CPU 读回，`correct=true`、`non_zero_pixels=64`，FNV-1a 哈希 `3acad6fd3214bd85`。
- 证据日志：`artifacts/physical-metal-probe/live-hilog.log`（原先的 `physical-metal-loader/metal-probe.json` 路径已不存在）。
- Rust 会话与回放：156 项通过，1 项设备捕获测试忽略。
- converter：34 项测试通过。
- Apple 原生 CARenderer 对照：Mac 上真实 QuartzCore scene 0 已渲染，全部 65,536 个像素通过背景、纯色和半透明混合的逐点断言；`nonzeroBytes=248544`，FNV-1a 哈希 `d15e8d0a54169a25`。BGRA 原始像素、身份和 MoltenVK 日志保存在 `artifacts/mac-ca-scene0/`。

## 当前边界

这次证明的是：真实 Metal shader/渲染管线可以在 Harmony Vulkan 上产生正确像素。它没有证明 Apple CALayer、CoreAnimation 事务或 SwiftUI 已能渲染。

当前 SwiftUI 窗口路径仍不能产生有效像素。`renderInContext` 返回成功和 NativeWindow 提交成功都不能作为内容证据；此前窗口快照的 nonBlack/nonTransparent 均为 0。

## 下一条最小接缝

使用真实 Apple `CALayer` 和 `CARenderer rendererWithMTLTexture:options:`，执行 `CATransaction.flush → beginFrameAtTime → addUpdateRect → render → endFrame → queue commit/wait → getBytes`，先验证参考项目 scene 0 的三种纯色/半透明图层。不要先接 render-server IPC、IOSurface、presentationLayer 或完整 UIWindow。

Rust runtime 已具备离屏 device/texture/queue/readback 后端；新增 harness 负责最小 Objective-C Metal 外壳。失败时记录缺失 selector，不用合成图层或固定 UI 代替。

## 2026-10-31 当前复验

- `tests/run_ca_renderer_mac.sh` 会将**同一份** `native/graphics/ca_renderer_probe.cpp` 与 Rust Metal 后端编进 macOS host harness，经 metal2vulkan → MoltenVK 执行真实 CALayer/CARenderer；它不是 Apple Metal 参考路径的替代名称。
- 该同外壳路径已验证真实 QuartzCore `default.metallib` fat 切片加载、device-backed 纹理 limits、60+5 等真实函数常量、顶点/混合描述、资源绑定和 4 次 indexed triangle draw。`beginFrame → render → endFrame → fence → readback` 全部执行，读回 65,536 个非透明像素，FNV-1a 与 Apple 参考完全一致，未实现 selector 为 0。成功报告 `artifacts/mac-ca-scene0/metal2vulkan-ca-report.json` 已通过独立严格校验；冷/热缓存两次日志为 `metal2vulkan-ca-success.log` 和 `metal2vulkan-ca-success-2.log`。这证明 scene 0 最小闭环，不证明完整 SwiftUI。
- 鸿蒙 `physical-ca-close-limits` 已越过原来的 IOSurface limits/`io_service_close` 停点。`physical-ca-singular-agx` 进一步验证 2880 单数 AGX 查询返回 `kIOReturnNotFound`，不再把空 iterator 当 service，且进入 transaction-flush；原先由伪 service 引发的 2889 已消失。随后 receive-only `io_main` 的 2809 `/product` 路径暴露了通用 IPC 缺少 `acquire_send`。`physical-ca-scene0-draw` 已验证该 transport 修复并收到 2909，但 `success + registry_entry=NULL` 后 CoreAnimation 仍断言，说明必须提供真实 `/product` IOPlatformDevice 及其实际属性。`physical-ca-gamut` 进一步验证：非空本地 registry service 的 `artwork-display-gamut` 查询已返回成功，属性值使用 Apple 原生 IOCFSerialize 的 `P3` 字节，并经 Apple 原生解析器复核。其后仍有独立 guest 断言，不能当作 frame/render 成功。
- `physical-ca-early-probe` 将独立探针前移到 UIKit 场景分析之前，排除了旧 SwiftUI 栈的干扰。后续已定位并补齐 vImage 所需 `__bsdthread_ctl(QOS_MAX_PARALLELISM)` 和 iOS 的 `_MTLCommandBuffer setResponsibleTaskIDs:count:`。
- **鸿蒙 scene 0 已通过**：`physical-ca-scene0-complete` 中，Maleoon 920C 执行 4 次真实 indexed draw、frame/fence/readback，`success=true`、65,536 个非透明像素、未实现 selector 为 0，独立严格校验通过。与 Apple 参考的唯一差异是红绿重叠区 4,800 个像素的 R 通道 128→127；仅替换这些像素即精确得到真机哈希 `8445581fde5db025`，因此以独立 `maleoon-920c-red-channel-minus-one` profile 验收，未使用通用容差。完整 SwiftUI 窗口呈现、连续帧、图片/文字、触摸和安全区仍未验证。
- `hm_ca_renderer_probe` 只有在完整帧 FNV-1a 等于 Apple 参考、像素覆盖计数一致、命令缓冲完成、没有未实现 selector 且没有 facade 错误时才能成功。`tests/ca_renderer_scene0.m --check-probe-report` 会拒绝不满足这些条件的报告。
- **scene 1 图片与裁剪也已通过**：`physical-ca-scene1-platform` 在 Maleoon 920C 上完成真实 RGBA 纹理上传、`replaceRegion`、`MTLSamplerState`、fragment texture/sampler binding 和纹理 indexed draw。`contentsRect` 与父层 `masksToBounds` 的全部 65,536 个像素均与同一 CARenderer/Metal 参考一致，FNV-1a=`71b0a93f2a0f4f25`，`pixelMismatchCount=0`，未实现 selector 为 0。scene 0 的独立回归未受影响。
- **scene 2 渐变已通过**：`physical-ca-scene2-samples` 在 Maleoon 920C 上完成真实 `CAGradientLayer` 的 BGRA10_XR 纹理上传和 indexed draw。默认 axial 红蓝渐变的全部 65,536 个像素及 32 行确定性抖动均与 Apple 参考一致，FNV-1a=`7103cb201d85fe35`，`pixelMismatchCount=0`，未实现 selector 为 0。独立校验同时检查 7 个原生样本和完整帧哈希。
- **scene 3 中文文字已通过（CoreText 路径）**：`physical-ca-scene3-retry` 使用随包 PingFangSC.ttf，在 guest 内通过真实 `CTLineDraw` 写入 224×64 BGRA CGBitmapContext，再生成 CGImage 交给普通 CALayer；不是 CATextLayer，也不是宿主光栅化。关闭字体平滑后，Mac 与鸿蒙的 262,144 字节完全一致，FNV-1a=`f30c0f733e400003`，未实现 selector 为 0。与 Apple 原生参考 `1ff8a71d36a1d74c` 的差异仅在 633 个 glyph 内像素且每通道最多 1 LSB，作为明确的 `coretext-native-arithmetic` profile 验收。CATextLayer 的字体服务注册路径仍未解决，未被当作成功。
- **真实窗口 CARenderer 路径已建立但 SwiftUI 内容未完成**：已创建真实 `UIWindowScene` 和 `UIHostingController<ContentView>`，并将 hosting layer 接入真实 CARenderer/Metal → fence/readback → OHNativeWindow。`physical-swiftui-set-scene` 中 renderer、frame、fence、readback 和 present 均成功，但帧仍全零。scene/lifecycle/content generation 尚未完成，不能宣称 SwiftUI Demo 已显示，也未开始触摸/安全区验收。
