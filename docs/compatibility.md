# 运行库与兼容层清单

此清单记录截至 2026-10-26 的实际输入与打包状态。真机调用栈已捕获原始 App 调用 `SwiftUI.App.main` 的返回地址；
`appExecuted=false` 字段仍缺少独立观测，不能用它否定该执行证据。不能把“库在缓存中”或“代码已打包”解释成运行兼容。

## 原版 Apple 运行库

证据来源是 `tools/hello-world-cache-pages.json`、本机生成的
`artifacts/ios27-aot/package.json` 与 `artifacts/ios27-cache-layout.json`。
本机 iOS 27 缓存包含 4691 个映像，目前选入 71 个映像的代码。
缓存 UUID 为 `55c72a0a0bfa3cd1b18ca83ff3411ac3`。

| 库 / 框架 | 已确认状态 | 接下来的验证 |
| --- | --- | --- |
| libobjc.A | 原版代码已选入；真机已执行到 ObjC 初始化 | 段间空洞修复已消除 overflow；继续处理 task MIG 3409 |
| libSystem.B、libsystem_kernel、libsystem_pthread、libdispatch、libxpc | 原版代码已选入 | 按真机实际调用补齐 Darwin / Mach 底层行为 |
| libswiftCore | 原版代码已实际执行 | 已通过 opaque descriptor 与导入 conformance descriptor 的认证；继续实际调用验证 |
| libswift_Concurrency | 原版代码已选入 | 继续验证 TLS、线程与并发初始化 |
| Foundation、CoreFoundation | 原版代码已选入 | 等待 dyld / ObjC 初始化完成后验证实际执行 |
| SwiftUI、SwiftUICore、UIKit、UIKitCore | 原版代码已选入 | 真机调用栈已包含 SwiftUI / UIKit；尚无渲染证据 |
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
- 先前 task MIG 3409 和 libdispatch XPC 接收超时已继续推进。本地传输验证
  `w00t` 端口描述符，并对 CFPreferences 操作 5 的批次及操作 1 的单条读取返回
  明确的后端不可用字典；没有返回成功读取或伪造偏好值。还未实现持久化偏好服务。
- `mach_generate_activity_id`（trap `-43`）已实现有界连续 ID 分配，真机通过。
  Activity 辅助向量按独立的 128 字节上限读取并校验，不与 XPC 主消息混合。
- 已更正先前地址归属：opaque descriptor 位于 App `__constg_swiftt` 的 `+0x4aec`，
  并非 guest 栈。打包器核验原始 ARM64 thunk、描述符头及 SwiftCore 绑定，native 仅在
  对应 cache UUID、认证指令、调用者和参数均匹配时签名临时寄存器值，再执行原版 AUTDA。
  导入的 `WindowGroup: Scene` descriptor 同样按导出、GOT 槽和调用点核验。
  两处真机认证均已通过。批量端口接口实现后，真机越过 Mach `-76`，
  最新重试 15,696 次转接后停在同步 Mach 消息 ID `6001013`，尚无 SwiftUI 输出。
- 签名 HAP 中 `getauxval(AT_HWCAP)=0xffffffff`，PACA/PACG 均置位。
  PACIBSP/AUTIBSP 与 PACIA/BLRAA 实际执行通过；未单独执行 PACGA 探针。
- Darwin / Mach 已有部分实现；以 `dyldBootstrap.unsupportedCalls` 和 trap 参数
  决定下一批接口。尚未实现的调用应保留真实错误或兼容报告，不能统一返回成功。
- Bootstrap / XPC 服务需要真实的端口与消息行为。当前尚未获得需要逐个实现的
  UI 服务调用证据，不能把架构文档中的服务示例当成已经观测到的缺口。
- CoreAnimation / IOSurface 到 Harmony NativeWindow 的输出桥接仍待实现和真机验证。
  原始 SwiftUI 显示结果是最终验收证据。

## 批量补齐与验证范围

先按子系统完成实现和本地回归，再统一构建安装。当前这批 Mach fast path 为：

| Trap | 本批实现 | 明确保留的边界 |
| --- | --- | --- |
| -76 port_type | 实际 send/receive 权位；NULL、DEAD、无效名称 | 外部 task |
| -16 port_allocate | 分配真实 receive right；复制失败回收未发布槽位 | port set、dead-name 分配 |
| -21 port_insert_right | 同名 MAKE_SEND / COPY_SEND，检查已有权并更新引用 | 异名转移及其他 disposition |
| -41 / -42 guard / unguard | 校验 receive right，保存/解除 guard，支持零值 | 需要 EXC_GUARD 投递的错误调用仍停止报告 |

内存复制错误使用 XNU `mach_copyout` 的 `KERN_MEMORY_ERROR=10`；guard 不匹配
不会修改原状态。已有线程创建/调度、完整本地 XPC 服务和图形输出尚未完成，
不能将这一批端口接口的通过解释成全部运行库兼容。下一批按真实调用与静态依赖清单扩展。

真机统一安装后，同一 PID 7705 三次重查为 15,648 / 15,663 / 15,696 次转接，
均保留原始 App `+0x44f8` 的返回帧。原始入口 `+0x44d4` 中的 `BL +0x4798`
位于 `+0x44f4`，该 stub 读取 GOT `+0x81f0` 绑定的 `SwiftUI.App.main`；
与返回帧吻合。证据见 `artifacts/ports-batch-evidence/app-main-stack-evidence.json`。
本批 109 项 Rust、38 项 Python 与 Clippy 通过；未重复安装逐个接口测试。

## 如何解读报告

`preflight` 是静态文件检查，不读取 native 层已映射的共享缓存，也不执行符号解析。
因此它现在用 `missingStandaloneImages` / `missingWeakStandaloneImages` 表示
“sysroot 下没有这个独立文件”，并明确给出 `cacheResolutionAttempted=false`。
这些列表不能直接显示成“缺少 iOS 运行库”。`missingFiles` 与 `missingWeakImages`
保留为空，因为静态检查尚不能确认库在所有装载来源中都不存在。

`availableSysrootFiles` 仅表示独立文件存在，`pacImages` 仅表示文件声明了相关
CPU subtype。它们都不能证明可执行。运行进度应读取 `dyldBootstrap`、真实 trap
与故障记录；静态报告不再硬编码“Apple dyld / PAC 未实现”或要求重新选择 Gate 0 路线。
