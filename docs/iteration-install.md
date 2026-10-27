# 签名 cache HSP 与迭代安装

2026-10-27，连接的 HarmonyOS ARM64 真机实测。

`ioscache` 是与 entry 相同 bundle/version/signing 配置的应用内 HSP。
它携带 cache 原生库；`harmonios` HAP 只包含可迭代的运行时、宿主和 App。
这沿用系统支持的 [HSP 部署方式](https://raw.githubusercontent.com/openharmony/docs/master/zh-cn/application-dev/quick-start/in-app-hsp.md)。

HAP CMake 不声明 cache 的 IMPORTED SHARED target，避免 Hvigor 将其复制到
HAP。运行时保留 `DT_NEEDED: libhm_ioscache.so`：真机的模块命名空间隔离使
单独 RTLD_GLOBAL 预加载不足以解析另一模块的符号，显式依赖可以正确绑定 HSP。
入口先通过小型 N-API loader 全局加载 cache，再加载 `libharmonios.so` 和其导出。
不改 guest 代码、PAC、Darwin 调用或运行时诊断边界。

## 文件一致性

- 当前选页 cache 在优化前 HAP 中为 **660806104 字节**；新增 EmojiFoundation
  及其依赖后，已大于最初安装优化请求中的 627 MB。
- HSP 内该库与优化前 HAP 内该库逐字节 SHA-256 一致：
  `f775cfef4e04e302f84d0749f02f92f43f3fa8d12fdee5c21bd8dfe5e8f121d6`。
- 新 HAP 为 **14465070 字节**，ZIP 内没有 `libhm_ioscache.so`。
- HSP 共 666234791 字节。首次传输使用 `hdc file send -z`，一次部署后复用。
- 初次 HSP 部署阶段实测 67.223 秒，其中 HSP 传输 55.551 秒；它不是后续每轮
  小 HAP 更新的耗时。首次 loader 原型缺少显式依赖，后续已修复并重新验收。

## 连续两轮验收

两轮命令均为：

```sh
python3 tools/run_device.py --skip-build --compressed-install \
  --no-stage-cache-data --no-warm-up --timeout 90 --output artifacts/<run>
```

| 指标 | hsp-reuse-run | hsp-reuse-repeat |
| --- | ---: | ---: |
| cache HSP | reuse，无传输 | reuse，无传输 |
| 校验已安装共享包 | 0.556s | 0.618s |
| HAP 传输 | 2.840s | 2.022s |
| bm install | 0.637s | 0.614s |
| 整个安装阶段 | **4.227s** | **3.479s** |
| appExecuted | true | true |
| traps | 262144 | 262144 |
| faultImage | /usr/lib/libobjc.A.dylib | /usr/lib/libobjc.A.dylib |

后三项与优化前 `artifacts/scene-options-run/` 基线一致。正常执行和独立 scene
探针仍未完成；scene 探针停在 Mach message 2884，帧数为 0。
这些指标证明部署优化没有提前终止已有执行路径，不能代替原版 SwiftUI 首帧验收。

原始证据在上述各目录的 `iteration-timings.json`、`device-compat-report.json`、
`fault-analysis.json` 和截图，汇总在 `artifacts/hsp-validation.json`。

## 复用和失效

`tools/cache_hsp.py` 对共享包全部 ZIP 成员名称、长度和内容计算 SHA-256，
单独保留 cache 库 SHA-256；外层签名块和 ZIP 时间戳不影响内容身份。
本地只对设备号、inode、大小、mtime、ctime 均未改变的已校验 HSP 复用摘要。
设备 stamp 在 HAP/HSP 安装成功后发布，并同时检查 Bundle Manager 中存在
`ioscache` 模块；缺 stamp、缺模块、共享包内容变化或强制刷新都会重新安装。
stamp 位于应用可调试文件目录，不能代替系统签名校验。

常规修改宿主/兼容层后运行：

```sh
python3 tools/run_device.py --no-clean --compressed-install --output artifacts/<run>
```

若共享包 app 版本或签名配置变化，需按系统的
[多模块一致性规则](https://raw.githubusercontent.com/openharmony/docs/master/zh-cn/application-dev/quick-start/install-and-update-consistency-verification.md)
重新构建；工具会根据新的内容身份更新共享包。
Apple 原生库和资源只保存在被 Git 忽略的本地产物目录中。

## 完整增量构建与审计复用

`artifacts/hsp-full-incremental/` 使用 `--no-clean --compressed-install`，实际
重建 HSP/HAP 后仍显示 `reuse installed cache HSP`，整个安装阶段为 4.224s。
新 HSP 外层签名/归档大小变化了 1 字节，但全部成员的内容身份未变，因此无需
重传；非执行 cache data 也显示 `reuse staged cache data`。

完整流程还会审计 AOT 执行页，确认 Darwin SVC/线程指针读取均已转换。
扫描本身需要遍历所有执行指令，原先即使输入未变也每轮重跑。
`audit_libsystem_shim.py --reuse` 现在只复用成功的本地结果：

- 输入身份涵盖原 cache 文件、执行页片段、package/layout，以及审计与 reader
  脚本；设备号、inode、大小、mtime、ctime 任一变化都失效。
- 复用前核对已验证报告的 SHA-256、成功状态与空 issues。
- 缺文件、损坏记录、失败扫描或扫描期间输入变化均不发布复用记录。
- 相对路径与绝对路径归一；修改 guest Darwin 兼容代码不会让未改变的 AOT 页
  重新接受全量扫描。省略 `--reuse` 仍执行完整审计。

runner 自动请求复用，并输出 `reuse verified Darwin boundary audit`。
此缓存只是避免重复的本地扫描，不改变 guest 指令或系统签名校验。

真实执行页完整扫描实测 84.152s；最终版本复用检查 0.146s，证据在
`artifacts/audit-reuse-timing.json`、`artifacts/audit-final-reuse-timing.json`。
56 项 Python 测试通过，覆盖复用及上述失效条件。

最终连续两轮完整增量命令（`hsp-incremental-final-1` / `-2`）都成功，HSP
及非执行 cache data 均复用，安装分别为 3.216s / 3.002s。
第一轮为当前审计代码建立新记录，命令总耗时 136.913s；第二轮显示审计 reuse，
总耗时 49.057s。总耗时还包含 HSP/HAP 构建、签名、原 App 执行及诊断采集，
不能将安装阶段的 3 秒当成整个迭代循环的耗时。
这两轮使用后续 IOKit 兼容修改；部署语义等价仍以上面固定运行时版本的
`hsp-reuse-run` / `hsp-reuse-repeat` 为验收，见 `docs/iokit-matching.md`。
