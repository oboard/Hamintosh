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

/**
 * Catalogue item model (MyApplication style).
 */
class CatalogueItemData {
  id: number = 0;
  title: string = '';
  subtitle: string = '';
  symbol: Resource = $r('sys.symbol.square_grid_2x2');

  constructor(id: number, title: string, subtitle: string, symbol: Resource) {
    this.id = id;
    this.title = title;
    this.subtitle = subtitle;
    this.symbol = symbol;
  }
}

/**
 * Catalogue list page view model (MyApplication style).
 */
class CatalogueViewModel {
  getCatalogueData(): CatalogueItemData[] {
    const catalogueData: CatalogueItemData[] = [
      new CatalogueItemData(1, '应用容器', 'Mach-O 原生执行容器与 CoreAnimation 界面呈现',
        $r('sys.symbol.square_grid_2x2')),
      new CatalogueItemData(2, '日志控制台', 'Guest TTY 与 Darwin 兼容层实时日志',
        $r('sys.symbol.doc_plaintext')),
      new CatalogueItemData(3, '系统设置', '执行门禁探针、内核兼容报告与规格',
        $r('sys.symbol.gearshape'))
    ];
    return catalogueData;
  }
}

const catalogueViewModel: CatalogueViewModel = new CatalogueViewModel();

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
  @State currentView: number = 0;

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

  // --- Top Navigation Header (ArkUI Standard Style) ---
  @Builder
  private topHeader(title: string, subtitle?: string) {
    Row() {
      Row({ space: 4 }) {
        SymbolGlyph($r('sys.symbol.chevron_left'))
          .fontSize(18)
          .fontColor([$r('app.color.text_primary')])
      }
      .width(36)
      .height(36)
      .justifyContent(FlexAlign.Center)
      .backgroundColor($r('app.color.card_background'))
      .borderRadius(18)
      .border({ width: 0.5, color: $r('app.color.border_subtle') })
      .margin({ right: 12 })
      .onClick(() => {
        this.currentView = 0;
      })

      Column({ space: 3 }) {
        Text(title)
          .fontSize(22)
          .fontWeight(FontWeight.Bold)
          .fontColor($r('app.color.text_primary'))
        if (subtitle) {
          Text(subtitle)
            .fontSize(12)
            .fontColor($r('app.color.text_secondary'))
        }
      }
      .alignItems(HorizontalAlign.Start)

      Blank()

      if (this.busy) {
        Row({ space: 6 }) {
          LoadingProgress()
            .width(16)
            .height(16)
            .color($r('app.color.accent'))
          Text('探测中')
            .fontSize(12)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('app.color.accent'))
        }
        .padding({ left: 10, right: 12, top: 5, bottom: 5 })
        .backgroundColor($r('app.color.accent_soft'))
        .borderRadius(14)
      } else {
        Row({ space: 4 }) {
          SymbolGlyph($r('sys.symbol.checkmark_circle_fill'))
            .fontSize(14)
            .fontColor(['#34C759'])
          Text('Darwin 就绪')
            .fontSize(12)
            .fontColor($r('app.color.text_secondary'))
        }
        .padding({ left: 8, right: 10, top: 4, bottom: 4 })
        .backgroundColor($r('app.color.card_background'))
        .borderRadius(12)
        .border({ width: 0.5, color: $r('app.color.border_subtle') })
      }
    }
    .width('100%')
    .height(56)
    .padding({ left: 16, right: 16 })
  }

  // --- Tab 0: Apps (TrollStore Style Application Container) ---
  @Builder
  private appsTab() {
    Column() {
      this.topHeader('应用容器', 'Mach-O 原生执行容器与界面呈现')

      List({ space: 14 }) {
        // App Card
        ListItem() {
          Column({ space: 14 }) {
            // Header: Icon + Metadata + Badges
            Row({ space: 14 }) {
              // HarmonyOS Squircle App Icon with Vector Glyphs
              Stack({ alignContent: Alignment.Center }) {
                // Background Gradient
                Column()
                  .width('100%')
                  .height('100%')
                  .backgroundColor('#007AFF')
                  .borderRadius(16)

                // Vector App Graphic
                SymbolGlyph($r('sys.symbol.square_grid_2x2'))
                  .fontSize(30)
                  .fontColor(['#FFFFFF'])
              }
              .width(60)
              .height(60)
              .borderRadius(16)
              .shadow({ radius: 8, color: '#33007AFF', offsetY: 4 })

              Column({ space: 4 }) {
                Row({ space: 8 }) {
                  Text(this.name)
                    .fontSize(17)
                    .fontWeight(FontWeight.Bold)
                    .fontColor($r('app.color.text_primary'))
                    .maxLines(1)
                    .textOverflow({ overflow: TextOverflow.Ellipsis })
                    .layoutWeight(1)

                  // Status Tag
                  Text(this.status === 'Launched' ? '已运行' : this.busy ? '初始化' : '就绪')
                    .fontSize(10)
                    .fontWeight(FontWeight.Medium)
                    .fontColor(this.status === 'Launched' ? '#34C759' : $r('app.color.text_secondary'))
                    .padding({ left: 6, right: 6, top: 2, bottom: 2 })
                    .backgroundColor(this.status === 'Launched' ? '#1534C759' : $r('app.color.inset_background'))
                    .borderRadius(4)
                }
                .width('100%')

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

                  Text('IPA 包体已挂载')
                    .fontSize(10)
                    .fontColor($r('app.color.text_secondary'))
                    .padding({ left: 6, right: 6, top: 2, bottom: 2 })
                    .backgroundColor($r('app.color.inset_background'))
                    .borderRadius(4)
                }
              }
              .layoutWeight(1)
              .alignItems(HorizontalAlign.Start)
            }
            .width('100%')

            Divider().color($r('app.color.border_subtle'))

            // Runtime Metrics & Action Button
            Row() {
              Column({ space: 2 }) {
                Text('目标指令集')
                  .fontSize(11)
                  .fontColor($r('app.color.text_secondary'))
                Text('ARM64e (PAC)')
                  .fontSize(14)
                  .fontWeight(FontWeight.Bold)
                  .fontColor($r('app.color.text_primary'))
              }
              .layoutWeight(1)
              .alignItems(HorizontalAlign.Start)

              Column({ space: 2 }) {
                Text('Darwin 转换门')
                  .fontSize(11)
                  .fontColor($r('app.color.text_secondary'))
                Text(`${this.dyldTraps} Traps`)
                  .fontSize(14)
                  .fontWeight(FontWeight.Bold)
                  .fontColor($r('app.color.text_primary'))
              }
              .layoutWeight(1)
              .alignItems(HorizontalAlign.Start)

              Button({ type: ButtonType.Capsule, stateEffect: true }) {
                Row({ space: 6 }) {
                  SymbolGlyph($r('sys.symbol.play_fill'))
                    .fontSize(14)
                    .fontColor([$r('app.color.on_accent')])
                  Text(this.busy ? '运行中…' : '打开应用')
                    .fontSize(13)
                    .fontWeight(FontWeight.Medium)
                    .fontColor($r('app.color.on_accent'))
                }
                .padding({ left: 14, right: 16, top: 8, bottom: 8 })
              }
              .backgroundColor($r('app.color.accent'))
              .enabled(!this.busy)
              .onClick(() => this.run())
            }
            .width('100%')
          }
          .padding(16)
          .backgroundColor($r('app.color.card_background'))
          .borderRadius(16)
          .border({ width: 0.5, color: $r('app.color.border_subtle') })
          .shadow({ radius: 8, color: '#0A000000', offsetY: 2 })
        }

        // CoreAnimation Surface Preview Card
        ListItem() {
          Column({ space: 12 }) {
            Row() {
              Row({ space: 6 }) {
                SymbolGlyph($r('sys.symbol.square_grid_2x2'))
                  .fontSize(15)
                  .fontColor([$r('app.color.accent')])
                Text('CoreAnimation 渲染图层')
                  .fontSize(15)
                  .fontWeight(FontWeight.Bold)
                  .fontColor($r('app.color.text_primary'))
              }

              Blank()

              Row({ space: 4 }) {
                SymbolGlyph(this.rendererStatus.includes('已连接') ?
                  $r('sys.symbol.checkmark_circle_fill') : $r('sys.symbol.dot_circle'))
                  .fontSize(12)
                  .fontColor([this.rendererStatus.includes('已连接') ? '#34C759' : $r('app.color.text_secondary')])
                Text(this.rendererStatus.includes('已连接') ? '连接就绪' : '等待连接')
                  .fontSize(11)
                  .fontColor(this.rendererStatus.includes('已连接') ? '#34C759' : $r('app.color.text_secondary'))
              }
            }
            .width('100%')

            Stack({ alignContent: Alignment.Center }) {
              XComponent({
                type: XComponentType.SURFACE,
                controller: this.renderController
              })
                .width('100%')
                .aspectRatio(9 / 16)
                .backgroundColor('#0A0E11')
                .onLoad(() => this.attachRenderSurface())
                .onDestroy(() => this.detachRenderSurface())

              if (this.rendererStatus.includes('等待')) {
                Column({ space: 10 }) {
                  LoadingProgress()
                    .width(28)
                    .height(28)
                    .color($r('app.color.accent'))
                  Text('等待 CoreAnimation 帧缓冲区挂载...')
                    .fontSize(12)
                    .fontColor($r('app.color.text_secondary'))
                }
              }
            }
            .width('100%')
            .borderRadius(14)
            .clip(true)
            .border({ width: 0.5, color: $r('app.color.border_subtle') })

            Text('注：原版 SwiftUI 应用窗口内容将通过 NativeWindow 接口无缝投影至上述图层。')
              .fontSize(11)
              .fontColor($r('app.color.text_tertiary'))
              .width('100%')
          }
          .padding(16)
          .backgroundColor($r('app.color.card_background'))
          .borderRadius(16)
          .border({ width: 0.5, color: $r('app.color.border_subtle') })
          .shadow({ radius: 8, color: '#0A000000', offsetY: 2 })
        }
      }
      .width('100%')
      .layoutWeight(1)
      .padding({ left: 16, right: 16, top: 4, bottom: 16 })
      .scrollBar(BarState.Off)
    }
    .width('100%')
    .height('100%')
  }

  // --- Tab 1: Logs (Dark Terminal Console) ---
  @Builder
  private consoleTab() {
    Column() {
      this.topHeader('运行日志', 'Darwin 兼容层与 Guest 终端')

      // Filter Segmented Controls
      Row({ space: 8 }) {
        Button({ type: ButtonType.Capsule }) {
          Row({ space: 4 }) {
            Text('全部日志')
              .fontSize(12)
              .fontWeight(this.logFilter === 'all' ? FontWeight.Medium : FontWeight.Normal)
              .fontColor(this.logFilter === 'all' ? $r('app.color.on_accent') : $r('app.color.text_secondary'))
          }
          .padding({ left: 12, right: 12, top: 6, bottom: 6 })
        }
        .backgroundColor(this.logFilter === 'all' ? $r('app.color.accent') : $r('app.color.inset_background'))
        .onClick(() => this.logFilter = 'all')

        Button({ type: ButtonType.Capsule }) {
          Row({ space: 4 }) {
            Text('Guest 控制台')
              .fontSize(12)
              .fontWeight(this.logFilter === 'guest' ? FontWeight.Medium : FontWeight.Normal)
              .fontColor(this.logFilter === 'guest' ? $r('app.color.on_accent') : $r('app.color.text_secondary'))
          }
          .padding({ left: 12, right: 12, top: 6, bottom: 6 })
        }
        .backgroundColor(this.logFilter === 'guest' ? $r('app.color.accent') : $r('app.color.inset_background'))
        .onClick(() => this.logFilter = 'guest')

        Button({ type: ButtonType.Capsule }) {
          Row({ space: 4 }) {
            Text('系统兼容日志')
              .fontSize(12)
              .fontWeight(this.logFilter === 'system' ? FontWeight.Medium : FontWeight.Normal)
              .fontColor(this.logFilter === 'system' ? $r('app.color.on_accent') : $r('app.color.text_secondary'))
          }
          .padding({ left: 12, right: 12, top: 6, bottom: 6 })
        }
        .backgroundColor(this.logFilter === 'system' ? $r('app.color.accent') : $r('app.color.inset_background'))
        .onClick(() => this.logFilter = 'system')
      }
      .width('100%')
      .padding({ left: 16, right: 16, top: 4, bottom: 8 })

      // Terminal Console Window
      Column() {
        // Terminal Window Header Bar
        Row({ space: 6 }) {
          Circle({ width: 8, height: 8 }).fill('#FF5F56')
          Circle({ width: 8, height: 8 }).fill('#FFBD2E')
          Circle({ width: 8, height: 8 }).fill('#27C93F')
          Blank()
          Text('bash - Harmonios Guest TTY')
            .fontSize(10)
            .fontFamily('monospace')
            .fontColor('#73858D')
          Blank()
        }
        .width('100%')
        .padding({ left: 12, right: 12, top: 8, bottom: 8 })
        .backgroundColor('#151B1E')
        .border({ width: { bottom: 0.5 }, color: '#24333B' })

        Scroll() {
          Column({ space: 4 }) {
            if (this.logFilter === 'all' || this.logFilter === 'system') {
              ForEach(this.systemLogs, (log: string) => {
                Text(log)
                  .fontSize(11)
                  .fontFamily('monospace')
                  .fontColor('#74DCC7')
                  .width('100%')
                  .copyOption(CopyOptions.InApp)
              })
            }
            if (this.logFilter === 'all' || this.logFilter === 'guest') {
              ForEach(this.guestLogs, (log: string) => {
                Text(`[Guest] ${log}`)
                  .fontSize(11)
                  .fontFamily('monospace')
                  .fontColor('#F2C47C')
                  .width('100%')
                  .copyOption(CopyOptions.InApp)
              })
            }
            if (this.systemLogs.length === 0 && this.guestLogs.length === 0) {
              Text('暂无日志输出，点击下方按钮唤起执行')
                .fontSize(12)
                .fontColor('#60747D')
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
      .backgroundColor('#10191E')
      .borderRadius(14)
      .clip(true)
      .border({ width: 0.5, color: '#30434C' })
      .shadow({ radius: 10, color: '#20000000', offsetY: 4 })
      .margin({ bottom: 12 })

      // Terminal Bottom Action Buttons
      Row({ space: 12 }) {
        Button({ type: ButtonType.Normal }) {
          Row({ space: 6 }) {
            SymbolGlyph($r('sys.symbol.trash'))
              .fontSize(14)
              .fontColor([$r('app.color.text_secondary')])
            Text('清空日志')
              .fontSize(13)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('app.color.text_primary'))
          }
          .padding({ top: 9, bottom: 9 })
          .justifyContent(FlexAlign.Center)
          .width('100%')
        }
        .layoutWeight(1)
        .borderRadius(12)
        .backgroundColor($r('app.color.inset_background'))
        .onClick(() => {
          this.systemLogs = [];
          this.guestLogs = [];
        })

        Button({ type: ButtonType.Normal }) {
          Row({ space: 6 }) {
            SymbolGlyph($r('sys.symbol.arrow_clockwise'))
              .fontSize(14)
              .fontColor([$r('app.color.on_accent')])
            Text('重新探测')
              .fontSize(13)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('app.color.on_accent'))
          }
          .padding({ top: 9, bottom: 9 })
          .justifyContent(FlexAlign.Center)
          .width('100%')
        }
        .layoutWeight(1)
        .borderRadius(12)
        .backgroundColor($r('app.color.accent'))
        .enabled(!this.busy)
        .onClick(() => this.run())
      }
      .width('100%')
      .padding({ left: 16, right: 16, bottom: 12 })
    }
    .width('100%')
    .height('100%')
  }

  // --- Tab 2: Settings & System Probes (Grouped List Style) ---
  @Builder
  private settingsTab() {
    Column() {
      this.topHeader('系统设置', 'Darwin 兼容层规格与环境诊断')

      List({ space: 16 }) {
        // Group 1: Probe Gate Overview
        ListItem() {
          Column({ space: 8 }) {
            Text('执行门禁与探针验证')
              .fontSize(13)
              .fontWeight(FontWeight.Medium)
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
            .borderRadius(16)
            .border({ width: 0.5, color: $r('app.color.border_subtle') })
            .shadow({ radius: 6, color: '#08000000', offsetY: 2 })
          }
          .width('100%')
        }

        // Group 2: Detailed Dyld & Kernel Report
        ListItem() {
          Column({ space: 8 }) {
            Text('Darwin 内核兼容报告')
              .fontSize(13)
              .fontWeight(FontWeight.Medium)
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
            .borderRadius(16)
            .border({ width: 0.5, color: $r('app.color.border_subtle') })
            .shadow({ radius: 6, color: '#08000000', offsetY: 2 })
          }
          .width('100%')
        }

        // Group 3: Architecture & About Specs
        ListItem() {
          Column({ space: 8 }) {
            Text('关于与规格')
              .fontSize(13)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('app.color.text_secondary'))
              .margin({ left: 4 })

            Column() {
              Row() {
                Text('版本')
                  .fontSize(14)
                  .fontColor($r('app.color.text_primary'))
                Blank()
                Text('v1.0.0 (ARM64 Native)')
                  .fontSize(14)
                  .fontColor($r('app.color.text_secondary'))
              }
              .width('100%')
              .padding({ top: 12, bottom: 12 })

              Divider().color($r('app.color.border_subtle'))

              Row() {
                Text('运行架构')
                  .fontSize(14)
                  .fontColor($r('app.color.text_primary'))
                Blank()
                Text('Mach-O → Signed ELF AOT')
                  .fontSize(14)
                  .fontColor($r('app.color.text_secondary'))
              }
              .width('100%')
              .padding({ top: 12, bottom: 12 })

              Divider().color($r('app.color.border_subtle'))

              Row() {
                Text('诊断报告路径')
                  .fontSize(14)
                  .fontColor($r('app.color.text_primary'))
                Blank()
                Row({ space: 4 }) {
                  Text(this.reportPath ? '已保存' : '未生成')
                    .fontSize(14)
                    .fontColor($r('app.color.text_secondary'))
                  SymbolGlyph($r('sys.symbol.chevron_right'))
                    .fontSize(12)
                    .fontColor([$r('app.color.text_tertiary')])
                }
              }
              .width('100%')
              .padding({ top: 12, bottom: 12 })
            }
            .width('100%')
            .padding({ left: 16, right: 16, top: 4, bottom: 4 })
            .backgroundColor($r('app.color.card_background'))
            .borderRadius(16)
            .border({ width: 0.5, color: $r('app.color.border_subtle') })
            .shadow({ radius: 6, color: '#08000000', offsetY: 2 })
          }
          .width('100%')
        }
      }
      .width('100%')
      .layoutWeight(1)
      .padding({ left: 16, right: 16, top: 4, bottom: 16 })
      .scrollBar(BarState.Off)
    }
    .width('100%')
    .height('100%')
  }

  // --- Catalogue Home (MyApplication Style Catalogue List) ---
  @Builder
  private catalogueHeader() {
    Row({ space: 14 }) {
      Stack({ alignContent: Alignment.Center }) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor($r('app.color.accent'))
          .borderRadius(16)
        SymbolGlyph($r('sys.symbol.square_grid_2x2'))
          .fontSize(30)
          .fontColor([$r('app.color.on_accent')])
      }
      .width(56)
      .height(56)
      .borderRadius(16)
      .shadow({ radius: 8, color: '#33007F73', offsetY: 4 })

      Column({ space: 4 }) {
        Text('Harmonios')
          .fontSize(24)
          .fontWeight(FontWeight.Bold)
          .fontColor($r('app.color.text_primary'))
        Text(this.busy ? '正在初始化 Darwin 运行环境...' : 'iOS 应用原生兼容运行环境')
          .fontSize(12)
          .fontColor($r('app.color.text_secondary'))
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)

      if (this.busy) {
        LoadingProgress()
          .width(22)
          .height(22)
          .color($r('app.color.accent'))
      } else {
        Row({ space: 4 }) {
          SymbolGlyph($r('sys.symbol.checkmark_circle_fill'))
            .fontSize(13)
            .fontColor(['#34C759'])
          Text('就绪')
            .fontSize(11)
            .fontColor($r('app.color.text_secondary'))
        }
        .padding({ left: 8, right: 10, top: 4, bottom: 4 })
        .backgroundColor($r('app.color.card_background'))
        .borderRadius(12)
        .border({ width: 0.5, color: $r('app.color.border_subtle') })
      }
    }
    .width('100%')
    .padding({ left: 20, right: 20, top: 12, bottom: 20 })
  }

  @Builder
  private catalogueListComponent(catalogue: CatalogueItemData[]) {
    Column() {
      GridRow({
        columns: { xs: 4, sm: 8, md: 12, lg: 12 },
        gutter: { x: 16 }
      }) {
        GridCol({
          span: { xs: 4, sm: 6, md: 8, lg: 8 },
          offset: { xs: 0, sm: 1, md: 2, lg: 2 }
        }) {
          List({ space: 12 }) {
            ForEach(catalogue, (item: CatalogueItemData) => {
              ListItem() {
                Row({ space: 14 }) {
                  SymbolGlyph(item.symbol)
                    .fontSize(24)
                    .fontColor([$r('app.color.on_accent')])

                  Column({ space: 3 }) {
                    Text(item.title)
                      .fontSize(17)
                      .fontWeight(FontWeight.Bold)
                      .fontColor($r('app.color.on_accent'))
                    Text(item.subtitle)
                      .fontSize(12)
                      .fontColor('#B3FFFFFF')
                      .maxLines(1)
                      .textOverflow({ overflow: TextOverflow.Ellipsis })
                  }
                  .layoutWeight(1)
                  .alignItems(HorizontalAlign.Start)

                  SymbolGlyph($r('sys.symbol.chevron_right'))
                    .fontSize(14)
                    .fontColor(['#80FFFFFF'])
                }
                .width('100%')
                .padding({ left: 18, right: 16 })
              }
              .backgroundColor($r('app.color.accent'))
              .width('100%')
              .height(76)
              .borderRadius(16)
              .shadow({ radius: 8, color: '#26007F73', offsetY: 3 })
              .onClick(() => {
                this.currentView = item.id;
                this.appendLog('system', `打开功能页: ${item.title}`);
              })
            }, (item: CatalogueItemData) => item.id.toString())
          }
          .width('100%')
          .scrollBar(BarState.Off)
        }
      }
    }
    .width('100%')
    .padding({ left: 16, right: 16 })
  }

  build() {
    Column() {
      if (this.currentView === 0) {
        Column() {
          this.catalogueHeader()
          this.catalogueListComponent(catalogueViewModel.getCatalogueData())

          Blank()

          Text('Harmonios v1.0.0 · Mach-O → Signed ELF AOT · ARM64e')
            .fontSize(11)
            .fontColor($r('app.color.text_tertiary'))
            .margin({ bottom: 16 })
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Start)
      } else if (this.currentView === 1) {
        this.appsTab()
      } else if (this.currentView === 2) {
        this.consoleTab()
      } else {
        this.settingsTab()
      }
    }
    .width('100%')
    .height('100%')
    .padding({ top: this.safeTop, bottom: this.safeBottom, left: this.safeLeft, right: this.safeRight })
    .backgroundColor($r('app.color.page_background'))
  }
}
