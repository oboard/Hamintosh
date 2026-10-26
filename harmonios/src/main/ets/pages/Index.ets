import { common } from '@kit.AbilityKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';
import { hilog } from '@kit.PerformanceAnalysisKit';
import runtime, { ProbeResult } from 'libharmonios.so';
import { probeRuntimeLoad } from 'libhm_load_probe.so';

interface TargetManifest {
  name: string;
  bundleId: string;
  minimumOS: string;
  sha256: string;
  executable: string;
  bundleDirectory: string;
  bundleFiles: string[];
}

interface SysrootManifest {
  files: string[];
}

interface ImageInfo {
  architecture: string;
  minimumOs: string;
  entryFileOffset: number;
  dependencies: Object[];
  undefinedSymbols: string[];
}

interface CompatReport {
  status: string;
  appExecuted: boolean;
  image?: ImageInfo;
  missingFiles?: string[];
  blockers?: string[];
  error?: string;
}

@Entry
@Component
struct Index {
  @State name: string = 'SwiftUIHelloWorld';
  @State bundleId: string = 'com.example.apple-samplecode.SwiftUIHelloWorld';
  @State status: string = 'Preparing runtime';
  @State bridge: string = 'Waiting for check';
  @State gate: string = 'Waiting for on-device execution probe';
  @State details: string = '';
  @State reportPath: string = '';
  @State busy: boolean = false;
  @State dyldTraps: number = 0;
  @State rendererStatus: string = 'Waiting for XComponent surface';
  @State activeTab: number = 0;

  // Real-time / aggregated logs extracted from dyld bootstrap & guest console
  @State guestLogs: string[] = [];
  @State systemLogs: string[] = [];
  @State logFilter: string = 'all';

  @StorageLink('safeTop') safeTop: number = 0;
  @StorageLink('safeBottom') safeBottom: number = 0;
  @StorageLink('safeLeft') safeLeft: number = 0;
  @StorageLink('safeRight') safeRight: number = 0;

  private renderController: XComponentController = new XComponentController();

  aboutToAppear(): void {
    this.appendLog('system', 'Harmonios 运行时环境初始化中...');
    this.run();
  }

  private appendLog(type: 'guest' | 'system', line: string): void {
    const time = new Date().toLocaleTimeString();
    const formatted = `[${time}] ${line}`;
    if (type === 'guest') {
      this.guestLogs.push(formatted);
    } else {
      this.systemLogs.push(formatted);
    }
  }

  private write(path: string, content: ArrayBuffer | string): void {
    const file = fs.openSync(path, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.TRUNC);
    try {
      fs.writeSync(file.fd, content);
    } finally {
      fs.closeSync(file);
    }
  }

  private async copyResource(context: common.UIAbilityContext, resource: string, path: string): Promise<void> {
    const bytes = await context.resourceManager.getRawFileContent(resource);
    this.write(path, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
  }

  private probeText(title: string, value: ProbeResult): string {
    if (value.status === 'passed') {
      return `${title}: returned ${value.value}`;
    }
    return `${title}: ${value.status} (errno ${value.errno}, signal ${value.signal})`;
  }

  private attachRenderSurface(): void {
    try {
      const surfaceId = this.renderController.getXComponentSurfaceId();
      const result = runtime.attachRenderSurface(surfaceId, 540, 960);
      this.rendererStatus = result.success ? 'NativeWindow 已连接；等待 CoreAnimation 首帧' :
        `NativeWindow 连接失败: ${result.status}`;
      this.appendLog('system', `RenderSurface 挂载: surfaceId=${surfaceId}, status=${result.status}`);
      hilog.info(0x484d, 'HarmoniosRender', 'surface=%{public}s status=%{public}s', surfaceId, result.status);
    } catch (error) {
      this.rendererStatus = `NativeWindow 连接失败: ${String(error)}`;
      this.appendLog('system', `RenderSurface 挂载异常: ${String(error)}`);
      hilog.error(0x484d, 'HarmoniosRender', '%{public}s', this.rendererStatus);
    }
  }

  private detachRenderSurface(): void {
    try {
      runtime.detachRenderSurface();
      this.appendLog('system', 'RenderSurface 已卸载');
    } catch (error) {
      hilog.error(0x484d, 'HarmoniosRender', 'surface detach failed: %{public}s', String(error));
    }
    this.rendererStatus = '等待 XComponent surface';
  }

  private async run(): Promise<void> {
    if (this.busy) {
      return;
    }
    this.busy = true;
    this.status = 'Checking';
    this.details = '';
    this.appendLog('system', '开始执行启动检查与 Darwin 兼容层探测...');
    try {
      if (!runtime) {
        throw new Error(probeRuntimeLoad());
      }
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const directory = `${context.filesDir}/probes`;
      if (!fs.accessSync(directory)) {
        fs.mkdirSync(directory, true);
      }
      for (const name of ['return42.macho', 'execution_probe.bin']) {
        const path = `${directory}/${name}`;
        await this.copyResource(context, `probes/${name}`, path);
      }
      const targetManifestBytes = await context.resourceManager.getRawFileContent('target/manifest.json');
      const manifest = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(
        new Uint8Array(targetManifestBytes.buffer.slice(targetManifestBytes.byteOffset,
          targetManifestBytes.byteOffset + targetManifestBytes.byteLength))
      )) as TargetManifest;
      this.name = manifest.name;
      this.bundleId = manifest.bundleId;
      this.appendLog('system', `解析目标 IPA 清单: ${manifest.name} (${manifest.bundleId})`);

      const appDirectory = `${context.filesDir}/apps/${manifest.bundleDirectory}`;
      if (!fs.accessSync(appDirectory)) {
        fs.mkdirSync(appDirectory, true);
      }
      for (const relative of manifest.bundleFiles) {
        if (relative.startsWith('/') || relative.split('/').includes('..')) {
          throw new Error('Bundle manifest contains an invalid relative path');
        }
        const path = `${appDirectory}/${relative}`;
        const parent = path.substring(0, path.lastIndexOf('/'));
        if (!fs.accessSync(parent)) {
          fs.mkdirSync(parent, true);
        }
        await this.copyResource(context, `target/bundle/${relative}`, path);
      }
      const sysrootManifestBytes = await context.resourceManager.getRawFileContent('sysroot/manifest.json');
      const sysrootManifest = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(
        new Uint8Array(sysrootManifestBytes.buffer.slice(sysrootManifestBytes.byteOffset,
          sysrootManifestBytes.byteOffset + sysrootManifestBytes.byteLength))
      )) as SysrootManifest;
      const sysrootFiles = sysrootManifest.files;
      const sysrootDirectory = `${context.filesDir}/sysroot`;
      if (!fs.accessSync(sysrootDirectory)) {
        fs.mkdirSync(sysrootDirectory, true);
      }
      for (const relative of sysrootFiles) {
        if (relative.startsWith('/') || relative.split('/').includes('..')) {
          throw new Error('Runtime library manifest contains an invalid path');
        }
        const path = `${sysrootDirectory}/${relative}`;
        const parent = path.substring(0, path.lastIndexOf('/'));
        if (!fs.accessSync(parent)) {
          fs.mkdirSync(parent, true);
        }
        await this.copyResource(context, `sysroot/${relative}`, path);
      }
      this.appendLog('system', 'iOS 运行库文件就绪，唤起 dyld 执行...');
      const result = await runtime.runDiagnostics(directory, `${appDirectory}/${manifest.executable}`,
        sysrootDirectory);
      const report = JSON.parse(result.compatReport) as CompatReport;
      const verification = result.runtimeVerification;
      report.appExecuted = verification.appExecuted;
      if (report.blockers) {
        report.blockers = report.blockers.filter((blocker: string) =>
          blocker !== 'runtime-execution-not-verified-by-static-inspection' ||
          !verification.runtimeExecutionVerified);
      }
      this.bridge = result.runtime;
      this.gate = [this.probeText('Raw ARM64 file', result.rawProbe),
        this.probeText('Mach-O file', result.machoProbe),
        this.probeText('Mach-O → Signed ELF', result.packagedProbe)].join('\n');
      this.gate += result.targetImage.status === 'mapped-awaiting-dyld' ?
        '\nTarget IPA: ARM64 image loaded; waiting for dynamic linking' : `\nTarget image: ${result.targetImage.status}`;
      this.gate += `\nDarwin probe: ${result.darwinProbe.status} (${result.darwinProbe.traps} transitions)`;
      this.gate += `\nARM64e pointer authentication: ${result.pacProbe.status}`;
      this.gate += `\nDarwin boot stack: ${result.bootStackProbe.status}`;
      this.gate += `\nARM64e pointer rebasing: ${result.rebaseProbe.status}`;
      this.gate += `\nApple dyld: ${result.dyldBootstrap.status} (${result.dyldBootstrap.traps} transitions)`;
      this.gate += verification.runtimeExecutionVerified ?
        '\nRuntime execution: verified by native probe' : '\nRuntime execution: not verified';
      this.dyldTraps = result.dyldBootstrap.traps;
      this.status = report.appExecuted ? 'Launched' : 'Launch blocked';

      this.appendLog('system', `执行结束: appExecuted=${verification.appExecuted}, dyldTraps=${result.dyldBootstrap.traps}`);

      // Extract console logs
      if (result.dyldBootstrap.message && result.dyldBootstrap.message.length > 0) {
        const msg = result.dyldBootstrap.message;
        const gcTag = 'guest console: ';
        const gcIdx = msg.indexOf(gcTag);
        if (gcIdx >= 0) {
          const endIdx = msg.indexOf('recent traps:', gcIdx);
          const rawConsole = endIdx > gcIdx ? msg.substring(gcIdx + gcTag.length, endIdx) : msg.substring(gcIdx + gcTag.length);
          const lines = rawConsole.split('\n');
          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.length > 0) {
              this.appendLog('guest', trimmed);
            }
          }
        }
        const uiTag = 'ui snapshot: ';
        const uiIdx = msg.indexOf(uiTag);
        if (uiIdx >= 0) {
          this.appendLog('system', msg.substring(uiIdx, Math.min(uiIdx + 300, msg.length)));
        }
      }

      const image = report.image;
      let summary = `Target system: iOS ${manifest.minimumOS}\n`;
      if (image) {
        summary += `Architecture: ${image.architecture}\nDependencies: ${image.dependencies.length} dynamic libraries\n`;
        summary += `Imported symbols: ${image.undefinedSymbols.length}\nEntry: 0x${image.entryFileOffset.toString(16)}\n`;
      }
      summary += '\nRuntime verification: ';
      summary += verification.runtimeExecutionVerified ? 'native probe observed Apple dyld' : 'not observed';
      summary += `\nApple dyld entered: ${verification.dyldEntered ? 'yes' : 'no'}`;
      summary += `\nApp entry executed: ${verification.appExecuted ? 'yes' : 'no'}`;
      summary += `\nRuntime status: ${verification.runtimeStatus || 'not run'}\n\n`;
      if (report.missingFiles && report.missingFiles.length > 0) {
        summary += `Missing iOS runtime libraries:\n${report.missingFiles.join('\n')}\n\n`;
      }
      if (report.blockers) {
        summary += `Unimplemented:\n${report.blockers.join('\n')}\n`;
      }
      if (report.error) {
        summary += report.error;
      }
      this.details = summary;
      if (result.dyldBootstrap.message.length > 0) {
        this.details += `\nLoader message: ${result.dyldBootstrap.message}\n`;
      }
      this.reportPath = `${context.filesDir}/compat-report.json`;
      const saved = `{"gate0":{"raw":${JSON.stringify(result.rawProbe)},` +
        `"macho":${JSON.stringify(result.machoProbe)},"packaged":${JSON.stringify(result.packagedProbe)}},` +
        `"target":${JSON.stringify(manifest)},"targetImage":${JSON.stringify(result.targetImage)},` +
        `"darwinProbe":${JSON.stringify(result.darwinProbe)},"pacProbe":${JSON.stringify(result.pacProbe)},` +
        `"bootStackProbe":${JSON.stringify(result.bootStackProbe)},` +
        `"rebaseProbe":${JSON.stringify(result.rebaseProbe)},` +
        `"dyldBootstrap":${JSON.stringify(result.dyldBootstrap)},` +
        `"runtimeVerification":${JSON.stringify(result.runtimeVerification)},` +
        `"preflight":${JSON.stringify(report)},` +
        `"frameDiagnostics":${result.frameDiagnostics || "{}"}}`;
      this.write(this.reportPath, saved);
      // Chunk the diagnostic so it can be retrieved on phones without sandbox file access.
      for (let offset = 0; offset < saved.length; offset += 700) {
        hilog.info(0x484d, 'HarmoniosReport', '%{public}d %{public}s', offset, saved.substring(offset, offset + 700));
      }
      hilog.info(0x484d, 'Harmonios', 'Gate0 %{public}s; appExecuted=%{public}s',
        this.gate, String(report.appExecuted));
    } catch (error) {
      this.status = 'Check failed';
      this.details = `Check failed: ${String(error)}`;
      this.appendLog('system', `执行出错: ${String(error)}`);
      hilog.error(0x484d, 'Harmonios', 'Execution failed: %{public}s', String(error));
    } finally {
      this.busy = false;
    }
  }

  // --- UI Components in TrollStore / Native HarmonyOS Style ---

  @Builder
  private topBar(title: string, subtitle?: string) {
    Row() {
      Column({ space: 2 }) {
        Text(title)
          .fontSize(22)
          .fontWeight(FontWeight.Bold)
          .fontColor($r('app.color.text_primary'))
        if (subtitle) {
          Text(subtitle)
            .fontSize(12)
            .fontColor($r('app.color.text_secondary'))
        }
      }.alignItems(HorizontalAlign.Start)
      Blank()
      if (this.busy) {
        Row({ space: 6 }) {
          LoadingProgress().width(16).height(16).color($r('app.color.accent'))
          Text('运行中')
            .fontSize(12)
            .fontColor($r('app.color.accent'))
        }
        .padding({ left: 10, right: 10, top: 4, bottom: 4 })
        .backgroundColor($r('app.color.accent_soft'))
        .borderRadius(12)
      }
    }
    .width('100%')
    .height(56)
    .padding({ left: 16, right: 16 })
    .backgroundColor($r('app.color.page_background'))
  }

  // Tab 0: Apps / Home (TrollStore style app list & current running app)
  @Builder
  private appsTab() {
    Column() {
      this.topBar('Harmonios', 'iOS 应用容器与安装器')
      Scroll() {
        Column({ space: 16 }) {
          // Current Selected App Card (iOS style list item / TrollStore app card)
          Column({ space: 14 }) {
            Row({ space: 12 }) {
              // App Icon Placeholder
              Stack() {
                Text('')
                  .fontSize(28)
                  .fontColor('#FFFFFF')
              }
              .width(56)
              .height(56)
              .borderRadius(14)
              .backgroundColor('#007AFF')
              .shadow({ radius: 8, color: '#33007AFF', offsetY: 4 })

              Column({ space: 4 }) {
                Text(this.name)
                  .fontSize(18)
                  .fontWeight(FontWeight.Bold)
                  .fontColor($r('app.color.text_primary'))
                Text(this.bundleId)
                  .fontSize(12)
                  .fontColor($r('app.color.text_secondary'))
                  .maxLines(1)
                  .textOverflow({ overflow: TextOverflow.Ellipsis })
                Row({ space: 6 }) {
                  Text('iOS 17.0+')
                    .fontSize(10)
                    .fontColor($r('app.color.accent'))
                    .padding({ left: 6, right: 6, top: 2, bottom: 2 })
                    .backgroundColor($r('app.color.accent_soft'))
                    .borderRadius(4)
                  Text(this.status === 'Launched' ? '已执行' : this.busy ? '启动中' : '就绪')
                    .fontSize(10)
                    .fontColor(this.status === 'Launched' ? '#34C759' : '#8E8E93')
                    .padding({ left: 6, right: 6, top: 2, bottom: 2 })
                    .backgroundColor(this.status === 'Launched' ? '#E8F8EE' : '#F2F2F7')
                    .borderRadius(4)
                }
              }
              .layoutWeight(1)
              .alignItems(HorizontalAlign.Start)
            }
            .width('100%')

            Divider().color($r('app.color.border_subtle'))

            // Actions & Metrics
            Row() {
              Column() {
                Text('指令集')
                  .fontSize(11)
                  .fontColor($r('app.color.text_secondary'))
                Text('ARM64e')
                  .fontSize(15)
                  .fontWeight(FontWeight.Bold)
                  .fontColor($r('app.color.text_primary'))
              }.layoutWeight(1).alignItems(HorizontalAlign.Start)

              Column() {
                Text('系统调用')
                  .fontSize(11)
                  .fontColor($r('app.color.text_secondary'))
                Text(this.dyldTraps.toString())
                  .fontSize(15)
                  .fontWeight(FontWeight.Bold)
                  .fontColor($r('app.color.text_primary'))
              }.layoutWeight(1).alignItems(HorizontalAlign.Start)

              Button(this.busy ? '启动中…' : '打开应用', { type: ButtonType.Capsule })
                .height(34)
                .fontSize(13)
                .fontWeight(FontWeight.Medium)
                .backgroundColor($r('app.color.accent'))
                .fontColor($r('app.color.on_accent'))
                .enabled(!this.busy)
                .onClick(() => this.run())
            }
            .width('100%')
          }
          .padding(16)
          .width('100%')
          .backgroundColor($r('app.color.card_background'))
          .borderRadius(16)
          .shadow({ radius: 8, color: '#0A000000', offsetY: 2 })

          // Screen / Graphics View
          Column({ space: 12 }) {
            Row() {
              Text('CoreAnimation 渲染输出')
                .fontSize(15)
                .fontWeight(FontWeight.Bold)
                .fontColor($r('app.color.text_primary'))
              Blank()
              Text(this.rendererStatus.includes('已连接') ? '连接正常' : '等待连接')
                .fontSize(11)
                .fontColor(this.rendererStatus.includes('已连接') ? '#34C759' : '#8E8E93')
            }.width('100%')

            Stack({ alignContent: Alignment.Center }) {
              XComponent({
                type: XComponentType.SURFACE,
                controller: this.renderController
              })
              .width('100%')
              .aspectRatio(9 / 16)
              .backgroundColor('#111111')
              .onLoad(() => this.attachRenderSurface())
              .onDestroy(() => this.detachRenderSurface())

              if (this.rendererStatus.includes('等待')) {
                Column({ space: 8 }) {
                  LoadingProgress().width(24).height(24).color('#888888')
                  Text('等待原生图层呈现...')
                    .fontSize(12)
                    .fontColor('#888888')
                }
              }
            }
            .width('100%')
            .borderRadius(12)
            .clip(true)

            Text('注：原版 SwiftUI 应用窗口内容将直接绘制在上述 Surface 中。')
              .fontSize(11)
              .fontColor($r('app.color.text_tertiary'))
              .width('100%')
          }
          .padding(16)
          .width('100%')
          .backgroundColor($r('app.color.card_background'))
          .borderRadius(16)
          .shadow({ radius: 8, color: '#0A000000', offsetY: 2 })
        }
        .padding({ left: 16, right: 16, top: 8, bottom: 24 })
      }
      .layoutWeight(1)
      .scrollBar(BarState.Off)
    }
    .width('100%')
    .height('100%')
  }

  // Tab 1: Real-time Logs Console
  @Builder
  private consoleTab() {
    Column() {
      this.topBar('运行日志', 'Darwin 兼容层与 Guest 终端')
      
      // Filter segments
      Row({ space: 8 }) {
        Button('全部日志', { type: ButtonType.Capsule })
          .fontSize(12)
          .height(30)
          .backgroundColor(this.logFilter === 'all' ? $r('app.color.accent') : $r('app.color.inset_background'))
          .fontColor(this.logFilter === 'all' ? $r('app.color.on_accent') : $r('app.color.text_secondary'))
          .onClick(() => this.logFilter = 'all')

        Button('Guest 控制台', { type: ButtonType.Capsule })
          .fontSize(12)
          .height(30)
          .backgroundColor(this.logFilter === 'guest' ? $r('app.color.accent') : $r('app.color.inset_background'))
          .fontColor(this.logFilter === 'guest' ? $r('app.color.on_accent') : $r('app.color.text_secondary'))
          .onClick(() => this.logFilter = 'guest')

        Button('系统兼容日志', { type: ButtonType.Capsule })
          .fontSize(12)
          .height(30)
          .backgroundColor(this.logFilter === 'system' ? $r('app.color.accent') : $r('app.color.inset_background'))
          .fontColor(this.logFilter === 'system' ? $r('app.color.on_accent') : $r('app.color.text_secondary'))
          .onClick(() => this.logFilter = 'system')
      }
      .width('100%')
      .padding({ left: 16, right: 16, top: 4, bottom: 8 })

      // Terminal container
      Column() {
        Scroll() {
          Column({ space: 4 }) {
            if (this.logFilter === 'all' || this.logFilter === 'system') {
              ForEach(this.systemLogs, (log: string) => {
                Text(log)
                  .fontSize(11)
                  .fontFamily('monospace')
                  .fontColor('#4CD964')
                  .width('100%')
                  .copyOption(CopyOptions.InApp)
              })
            }
            if (this.logFilter === 'all' || this.logFilter === 'guest') {
              ForEach(this.guestLogs, (log: string) => {
                Text(`[Guest] ${log}`)
                  .fontSize(11)
                  .fontFamily('monospace')
                  .fontColor('#FFD60A')
                  .width('100%')
                  .copyOption(CopyOptions.InApp)
              })
            }
            if (this.systemLogs.length === 0 && this.guestLogs.length === 0) {
              Text('暂无日志输出，点击下方按钮唤起执行')
                .fontSize(12)
                .fontColor('#8E8E93')
                .margin({ top: 32 })
            }
          }
          .padding(12)
          .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .scrollBar(BarState.Auto)
      }
      .width('92%')
      .layoutWeight(1)
      .backgroundColor('#1C1C1E')
      .borderRadius(12)
      .margin({ bottom: 12 })

      // Bottom bar for clear / copy
      Row({ space: 12 }) {
        Button('清空日志', { type: ButtonType.Normal })
          .fontSize(12)
          .height(36)
          .layoutWeight(1)
          .borderRadius(10)
          .backgroundColor($r('app.color.inset_background'))
          .fontColor($r('app.color.text_primary'))
          .onClick(() => {
            this.systemLogs = [];
            this.guestLogs = [];
          })

        Button('重新执行探针', { type: ButtonType.Normal })
          .fontSize(12)
          .height(36)
          .layoutWeight(1)
          .borderRadius(10)
          .backgroundColor($r('app.color.accent'))
          .fontColor($r('app.color.on_accent'))
          .enabled(!this.busy)
          .onClick(() => this.run())
      }
      .width('100%')
      .padding({ left: 16, right: 16, bottom: 12 })
    }
    .width('100%')
    .height('100%')
  }

  // Tab 2: Settings & Detailed System Diagnostics (TrollStore Settings style)
  @Builder
  private settingsTab() {
    Column() {
      this.topBar('设置与诊断', '兼容性详情与环境配置')
      Scroll() {
        Column({ space: 16 }) {
          // Probe Gate Overview
          Column({ space: 8 }) {
            Text('执行门禁与探针验证')
              .fontSize(13)
              .fontWeight(FontWeight.Bold)
              .fontColor($r('app.color.text_secondary'))
              .margin({ left: 4 })

            Column({ space: 10 }) {
              Text(this.gate)
                .fontSize(12)
                .lineHeight(20)
                .fontFamily('monospace')
                .fontColor($r('app.color.text_primary'))
                .copyOption(CopyOptions.InApp)
            }
            .width('100%')
            .padding(16)
            .backgroundColor($r('app.color.card_background'))
            .borderRadius(14)
          }
          .width('100%')

          // Detailed Dyld & Kernel Report
          Column({ space: 8 }) {
            Text('Darwin 内核兼容报告')
              .fontSize(13)
              .fontWeight(FontWeight.Bold)
              .fontColor($r('app.color.text_secondary'))
              .margin({ left: 4 })

            Column({ space: 10 }) {
              Text(this.details || '等待生成诊断...')
                .fontSize(11)
                .lineHeight(18)
                .fontFamily('monospace')
                .fontColor($r('app.color.text_secondary'))
                .copyOption(CopyOptions.InApp)
            }
            .width('100%')
            .padding(16)
            .backgroundColor($r('app.color.card_background'))
            .borderRadius(14)
          }
          .width('100%')

          // About Harmonios
          Column({ space: 8 }) {
            Text('关于')
              .fontSize(13)
              .fontWeight(FontWeight.Bold)
              .fontColor($r('app.color.text_secondary'))
              .margin({ left: 4 })

            Column({ space: 6 }) {
              Row() {
                Text('版本').fontSize(14).fontColor($r('app.color.text_primary'))
                Blank()
                Text('v1.0.0 (ARM64 Native)').fontSize(14).fontColor($r('app.color.text_secondary'))
              }.width('100%').padding({ top: 8, bottom: 8 })

              Divider().color($r('app.color.border_subtle'))

              Row() {
                Text('运行架构').fontSize(14).fontColor($r('app.color.text_primary'))
                Blank()
                Text('Mach-O → Signed ELF AOT').fontSize(14).fontColor($r('app.color.text_secondary'))
              }.width('100%').padding({ top: 8, bottom: 8 })

              Divider().color($r('app.color.border_subtle'))

              Row() {
                Text('诊断报告路径').fontSize(14).fontColor($r('app.color.text_primary'))
                Blank()
                Text(this.reportPath ? '已保存' : '未生成').fontSize(14).fontColor($r('app.color.text_secondary'))
              }.width('100%').padding({ top: 8, bottom: 8 })
            }
            .width('100%')
            .padding({ left: 16, right: 16, top: 4, bottom: 4 })
            .backgroundColor($r('app.color.card_background'))
            .borderRadius(14)
          }
          .width('100%')
        }
        .padding({ left: 16, right: 16, top: 8, bottom: 24 })
      }
      .layoutWeight(1)
      .scrollBar(BarState.Off)
    }
    .width('100%')
    .height('100%')
  }

  // Bottom Navigation Bar (TrollStore style: Apps, Logs, Settings)
  @Builder
  private bottomTabBar() {
    Row() {
      // Tab 0: Apps
      Column({ space: 4 }) {
        Text('📱')
          .fontSize(18)
        Text('应用')
          .fontSize(10)
          .fontWeight(this.activeTab === 0 ? FontWeight.Bold : FontWeight.Normal)
          .fontColor(this.activeTab === 0 ? $r('app.color.accent') : $r('app.color.text_secondary'))
      }
      .layoutWeight(1)
      .height('100%')
      .justifyContent(FlexAlign.Center)
      .onClick(() => this.activeTab = 0)

      // Tab 1: Logs
      Column({ space: 4 }) {
        Text('📄')
          .fontSize(18)
        Text('日志')
          .fontSize(10)
          .fontWeight(this.activeTab === 1 ? FontWeight.Bold : FontWeight.Normal)
          .fontColor(this.activeTab === 1 ? $r('app.color.accent') : $r('app.color.text_secondary'))
      }
      .layoutWeight(1)
      .height('100%')
      .justifyContent(FlexAlign.Center)
      .onClick(() => this.activeTab = 1)

      // Tab 2: Settings
      Column({ space: 4 }) {
        Text('⚙️')
          .fontSize(18)
        Text('设置')
          .fontSize(10)
          .fontWeight(this.activeTab === 2 ? FontWeight.Bold : FontWeight.Normal)
          .fontColor(this.activeTab === 2 ? $r('app.color.accent') : $r('app.color.text_secondary'))
      }
      .layoutWeight(1)
      .height('100%')
      .justifyContent(FlexAlign.Center)
      .onClick(() => this.activeTab = 2)
    }
    .width('100%')
    .height(56)
    .backgroundColor($r('app.color.card_background'))
    .border({ width: { top: 0.5 }, color: $r('app.color.border_subtle') })
  }

  build() {
    Column() {
      // Main Page Body according to current Tab
      Column() {
        if (this.activeTab === 0) {
          this.appsTab()
        } else if (this.activeTab === 1) {
          this.consoleTab()
        } else {
          this.settingsTab()
        }
      }
      .width('100%')
      .layoutWeight(1)

      // Bottom Navigation Bar
      this.bottomTabBar()
    }
    .width('100%')
    .height('100%')
    .padding({ top: this.safeTop, bottom: this.safeBottom, left: this.safeLeft, right: this.safeRight })
    .backgroundColor($r('app.color.page_background'))
  }
}
