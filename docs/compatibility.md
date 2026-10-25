# 运行库与兼容层清单

此清单记录 2026-10-25 的实际输入与打包状态。原版 App 的入口尚未执行，
`appExecuted=false`；不能把“库在缓存中”或“代码已打包”解释成运行兼容。

## 原版 Apple 运行库

证据来源是 `tools/hello-world-cache-pages.json`、本机生成的
`artifacts/ios27-aot/package.json` 与 `artifacts/ios27-cache-layout.json`。
本机 iOS 27 缓存包含 4691 个映像，目前选入 71 个映像的代码。
缓存 UUID 为 `55c72a0a0bfa3cd1b18ca83ff3411ac3`。

| 库 / 框架 | 已确认状态 | 接下来的验证 |
| --- | --- | --- |
| libobjc.A | 原版代码已选入；真机已执行到 ObjC 初始化 | 段间空洞修复已消除 overflow；继续处理 task MIG 3409 |
| libSystem.B、libsystem_kernel、libsystem_pthread、libdispatch、libxpc | 原版代码已选入 | 按真机实际调用补齐 Darwin / Mach 底层行为 |
| libswiftCore、libswift_Concurrency | 原版代码已选入 | 继续验证 TLS、分配、线程与并发初始化 |
| Foundation、CoreFoundation | 原版代码已选入 | 等待 dyld / ObjC 初始化完成后验证实际执行 |
| SwiftUI、SwiftUICore、UIKit、UIKitCore | 原版代码已选入 | 进入原始 App 后验证；尚无渲染证据 |
| QuartzCore、CoreGraphics、IOSurface、Metal、AttributeGraph | 存在于原始缓存；未选入完整可执行代码 | 按真实执行依赖加入签名 ELF，并实现所需系统桥接 |
| libPlaygrounds | App 以弱依赖声明；未在这套原始缓存中找到 | 观察原版 dyld 对弱依赖和弱符号的实际处理 |

只读元数据和非执行数据由独立 data pack 提供；它们不授予执行权限。
未选入某库的代码与缺少该库的原始文件是不同状态。对全量传递依赖的覆盖仍未完成。

## 需要继续适配的底层能力

- 已定位此前 Apple libobjc 的 `entsize_list_tt overflow` 来源：OHOS musl
  装载稀疏 ELF 时，覆盖 `PT_LOAD` 前建立的整段可读文件映射残留在段间空洞。
  对 cache-relative `0x47e4d80` 的列表读取因而未触发 data pager，而是读到 ELF
  同偏移的无关指令；其 count 字段正好为真机报出的 `0x52800000`。原始缓存与
  data pack 中的正确 count 均为 `5`。native 层已在 guest 执行前将这些空洞
  设为 `PROT_NONE`，让首次访问从原始数据源分页；真机验证已消除该 overflow。
  此问题不要求重写 libobjc，也不能通过跳过原版列表检查处理。
- Darwin `gettimeofday`（syscall 116）已实现日历时间、微秒、时区和私有 absolute
  time 输出，按 guest ABI 编码，并通过边界与错误路径测试；真机已多次执行成功。
- Darwin BSD `mprotect`（syscall 74）的兼容分派正在独立实现；需沿用已有 guest VM
  权限检查与 native 保护机制，再用实际执行验证，不能授予未签名代码执行权限。
- 最新真机执行 908 次转接，停在 `mach_msg2`（trap `-47`）向 task port
  `0x103` 发送的 MIG 请求 `3409`（`0xd51`，36 字节）；正在实现其具体语义。
- Darwin / Mach 已有部分实现；以 `dyldBootstrap.unsupportedCalls` 和 trap 参数
  决定下一批接口。尚未实现的调用应保留真实错误或兼容报告，不能统一返回成功。
- Bootstrap / XPC 服务需要真实的端口与消息行为。当前尚未获得需要逐个实现的
  UI 服务调用证据，不能把架构文档中的服务示例当成已经观测到的缺口。
- CoreAnimation / IOSurface 到 Harmony NativeWindow 的输出桥接仍待实现和真机验证。
  原始 SwiftUI 显示结果是最终验收证据。

## 如何解读报告

`preflight` 是静态文件检查，不读取 native 层已映射的共享缓存，也不执行符号解析。
因此它现在用 `missingStandaloneImages` / `missingWeakStandaloneImages` 表示
“sysroot 下没有这个独立文件”，并明确给出 `cacheResolutionAttempted=false`。
这些列表不能直接显示成“缺少 iOS 运行库”。`missingFiles` 与 `missingWeakImages`
保留为空，因为静态检查尚不能确认库在所有装载来源中都不存在。

`availableSysrootFiles` 仅表示独立文件存在，`pacImages` 仅表示文件声明了相关
CPU subtype。它们都不能证明可执行。运行进度应读取 `dyldBootstrap`、真实 trap
与故障记录；静态报告不再硬编码“Apple dyld / PAC 未实现”或要求重新选择 Gate 0 路线。
