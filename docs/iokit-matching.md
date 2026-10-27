# HID matching notification compatibility

2026-10-27，原始 iOS 27.0 cache、HarmonyOS ARM64 真机。
此项是签名 HSP 部署优化之后的独立运行时推进，不属于部署前后语义等价的验收。

## 观测到的请求

独立 scene 探针原先在 Mach message 2884 停止。现在探针也保存最后一次完整
Mach send 数据，避免用主运行阶段的其他请求体推断协议。
`artifacts/mig2884-capture-run/` 中的请求长 212 字节：

| 字段 | 内容 |
| --- | --- |
| destination | 已建立的本地 `io_main_port` |
| reply | 线程的 special reply port |
| descriptor | 一个 MAKE_SEND 通知接收端口 |
| notification type | `IOServiceFirstMatch` |
| matching | 104 字节 IOCF binary dictionary |
| provider class | `IOHIDDevice` |
| DeviceUsagePage / DeviceUsage | 1 / 5，即 Generic Desktop / Game Pad |
| async reference count | 3；其中的 callback/context 保持原始 64 位，包括 PAC |

原始 IOKit 调用点在 preferred address `0x18f082738`，生成的 MIG 客户端在
`0x18f0828ac`。字段布局同时对照本机 XNU 源码 `osfmk/device/device.defs` 中
64 位 notification/bin 接口；对象耗尽与 armed 行为对照
`iokit/Kernel/IOUserClient.cpp` 的 `is_io_iterator_next` 和
`IOServiceUserNotification::copyNextObject`。

## 本地对象与边界

`runtime/src/darwin/iokit.rs` 保存有界的 32 个订阅。只接受已解码的 HID class
及可选 usage/page 数值；未知 matching 语法仍停在明确的未实现边界。
订阅保存规则、通知类型、端口和 opaque callback references。

当前本地注册表没有 IOHIDDevice。注册返回一个拥有独立 send right 的通知
迭代器；`IOIteratorNext` (2802) 返回 `kIOReturnNoDevice` 的 MIG error reply，
并将订阅 armed。它不产生设备、不调用 guest callback，也不声称输入后端已完成。
以后若注册真实 HID 设备，需要继续实现匹配、异步消息和设备移除。

迭代器的最后一个 send reference 释放后回收订阅及其保留的 wake right；
retain/release、端口代际、copyout 失败回滚和容量恢复均有协议测试。
测试使用程序构造的请求，仓库中不提交 Apple 库或原始二进制请求。

## 真机验证

签名小 HAP 构建成功，163 项 Rust 测试通过、1 项本机 capture 测试忽略；
Clippy 按 warnings as errors 通过。

| 指标 | iokit-notify-run | iokit-notify-repeat |
| --- | ---: | ---: |
| cache HSP | reuse | reuse |
| 安装总耗时 | 2.383s | 2.548s |
| appExecuted / 正常运行 traps | true / 262144 | true / 262144 |
| scene 探针 traps | 49814 | 49947 |
| scene 探针 fault PC（cache offset） | 0x5c39d278 | 0x5c39d278 |
| worker primaryFault | 全部 0 | 全部 0 |
| Apple 帧 | 0 | 0 |

两轮独立 scene 探针均越过 2884，随后在尚未选入签名 ELF 的
`/usr/lib/libMobileGestaltExtensions.dylib` 执行页发生 SIGSEGV。
调用者为 `libMobileGestalt.dylib`，LR 的 cache offset 为 `0x2f9eb440`。
报告中的 `inspectionSyscall=-14` 是最后一次已处理 trap，当前停止原因是执行页
故障，不是 Mach -14 未实现。

正常主运行的 trap 上限落点受线程交错影响，两轮分别在 libobjc 和
libsystem_kernel；不把这种落点差异归因于 HSP，也不把后续运行时改动混入
`artifacts/hsp-validation.json` 中固定版本的部署等价验收。

UIScene/window 仍为空。该探针在主运行停止后执行，不是正常 FrontBoard scene
交付；目前没有原 App 的 SwiftUI 首帧证据。
