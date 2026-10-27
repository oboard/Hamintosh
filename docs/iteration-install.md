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
