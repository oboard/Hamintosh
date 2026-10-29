import { common, Want } from '@kit.AbilityKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { promptAction, uiMaterial } from '@kit.ArkUI';
import { loadRuntime, RuntimeExports, ProbeResult } from 'libhm_load_probe.so';
import { cacheLibraryName } from 'ioscache';

interface TargetManifest {
  name: string;
  bundleId: string;
  minimumOS: string;
  sha256?: string;
  executable: string;
  bundleDirectory: string;
  bundleFiles: string[];
  version?: string;
  size?: string;
  icon?: string;
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

interface AppItem {
  id: string;
  name: string;
  bundleId: string;
  icon: ResourceStr;
  versionInfo: string;
  isRunnable: boolean;
}

@Entry
@Component
struct Index {
  @State name: string = 'SwiftUIHelloWorld';
  @State bundleId: string = 'devplaceholder.HDPAWPTN.SwiftUIHelloWorld';
  @State status: string = 'Preparing runtime';
  @State bridge: string = 'Waiting for check';
  @State gate: string = 'Waiting for on-device execution probe';
  @State details: string = '';
  @State reportPath: string = '';
  @State busy: boolean = false;
  @State dyldTraps: number = 0;
  @State rendererStatus: string = 'Waiting for XComponent surface';
  @State currentTabIndex: number = 0;
  @State activeAppRunning: boolean = false;
  @State appsList: AppItem[] = [];

  // Real-time / aggregated logs extracted from dyld bootstrap & guest console
  @State guestLogs: string[] = [];
  @State systemLogs: string[] = [];
  @State logFilter: string = 'all';

  @StorageLink('safeTop') safeTop: number = 0;
  @StorageLink('safeBottom') safeBottom: number = 0;
  @StorageLink('safeLeft') safeLeft: number = 0;
  @StorageLink('safeRight') safeRight: number = 0;

  private renderController: XComponentController = new XComponentController();
  private tabsController: TabsController = new TabsController();

  private runtime?: RuntimeExports;

  private ensureRuntime(): RuntimeExports {
    if (!this.runtime) { this.runtime = loadRuntime(cacheLibraryName); }
    return this.runtime;
  }

  aboutToAppear(): void {
    this.appendLog('system', 'Harmonios runtime initializing...');
    this.loadInstalledApps();
    setTimeout(() => {
      this.run();
    }, 400);
  }

  onPageShow(): void {
    this.loadInstalledApps();
  }

  private resolveAppIcon(appDirectory: string, manifestIcon?: string): ResourceStr {
    try {
      if (manifestIcon) {
        if (fs.accessSync(manifestIcon)) {
          return `file://${manifestIcon}`;
        }
        const fromAppDir = `${appDirectory}/${manifestIcon}`;
        if (fs.accessSync(fromAppDir)) {
          return `file://${fromAppDir}`;
        }
      }
      if (fs.accessSync(appDirectory)) {
        const files = fs.listFileSync(appDirectory);
        let candidate = files.find((f: string) => f.toLowerCase().includes('icon') && f.endsWith('.png'));
        if (!candidate) {
          candidate = files.find((f: string) => f.endsWith('.png'));
        }
        if (candidate) {
          return `file://${appDirectory}/${candidate}`;
        }
      }
    } catch (_) {}
    return $r('app.media.startIcon');
  }

  private getAppSize(appDir: string, fallbackSize: string): string {
    try {
      if (fs.accessSync(appDir)) {
        let total = 0;
        const calcDir = (dir: string): void => {
          const files = fs.listFileSync(dir);
          for (const f of files) {
            const p = `${dir}/${f}`;
            try {
              const stat = fs.statSync(p);
              if (stat.isDirectory()) {
                calcDir(p);
              } else {
                total += stat.size;
              }
            } catch (_) {}
          }
        };
        calcDir(appDir);
        if (total > 0) {
          if (total < 1024 * 1024) {
            return `${Math.round(total / 1024)} KB`;
          } else {
            return `${(total / (1024 * 1024)).toFixed(1)} MB`;
          }
        }
      }
    } catch (_) {}
    return fallbackSize;
  }

  private async loadInstalledApps(): Promise<void> {
    const list: AppItem[] = [];
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const targetManifestBytes = await context.resourceManager.getRawFileContent('target/manifest.json');
      const manifest = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(
        new Uint8Array(targetManifestBytes.buffer.slice(targetManifestBytes.byteOffset,
          targetManifestBytes.byteOffset + targetManifestBytes.byteLength))
      )) as TargetManifest;
      this.name = manifest.name;
      this.bundleId = manifest.bundleId;

      const appDir = `${context.filesDir}/apps/${manifest.bundleDirectory}`;
      const icon = this.resolveAppIcon(appDir, manifest.icon);
      const version = manifest.version || '1.0';
      const size = manifest.size || (manifest.name === 'SwiftUIHelloWorld' ? '92 KB' : this.getAppSize(appDir, '92 KB'));
      const desc = `${version} · ${manifest.bundleId} · ${size}`;

      list.push({
        id: manifest.bundleId,
        name: manifest.name,
        bundleId: manifest.bundleId,
        icon: icon,
        versionInfo: desc,
        isRunnable: true
      });
    } catch (e) {
      hilog.warn(0x484d, 'Harmonios', 'Failed to load target manifest: %{public}s', String(e));
    }

    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const appsDir = `${context.filesDir}/apps`;
      if (fs.accessSync(appsDir)) {
        const entries = fs.listFileSync(appsDir);
        for (const entry of entries) {
          if (entry.endsWith('.app') && !list.some(a => a.name === entry.replace('.app', '') || a.id === entry.replace('.app', ''))) {
            const manifestPath = `${appsDir}/${entry}/manifest.json`;
            if (fs.accessSync(manifestPath)) {
              try {
                const content = fs.readTextSync(manifestPath);
                const extra = JSON.parse(content) as TargetManifest;
                const appDir = `${appsDir}/${entry}`;
                const icon = this.resolveAppIcon(appDir, extra.icon);
                const version = extra.version || '1.0';
                const size = extra.size || this.getAppSize(appDir, '128 MB');
                list.push({
                  id: extra.bundleId,
                  name: extra.name,
                  bundleId: extra.bundleId,
                  icon: icon,
                  versionInfo: `${version} · ${extra.bundleId} · ${size}`,
                  isRunnable: true
                });
              } catch (_) {}
            }
          }
        }
      }
    } catch (_) {}

    this.appsList = list;
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
      const result = this.ensureRuntime().attachRenderSurface(surfaceId, 540, 960);
      this.rendererStatus = result.success ? 'NativeWindow Connected' :
        `NativeWindow Connection Failed: ${result.status}`;
      this.appendLog('system', `RenderSurface attached: surfaceId=${surfaceId}, status=${result.status}`);
      hilog.info(0x484d, 'HarmoniosRender', 'surface=%{public}s status=%{public}s', surfaceId, result.status);
    } catch (error) {
      this.rendererStatus = `NativeWindow Connection Failed: ${String(error)}`;
      this.appendLog('system', `RenderSurface attach error: ${String(error)}`);
      hilog.error(0x484d, 'HarmoniosRender', '%{public}s', this.rendererStatus);
    }
  }

  private detachRenderSurface(): void {
    try {
      this.ensureRuntime().detachRenderSurface();
      this.appendLog('system', 'RenderSurface detached');
    } catch (error) {
      hilog.error(0x484d, 'HarmoniosRender', 'surface detach failed: %{public}s', String(error));
    }
    this.rendererStatus = 'Waiting for XComponent surface';
  }

  private async run(): Promise<void> {
    if (this.busy) {
      return;
    }
    this.busy = true;
    this.status = 'Checking';
    this.details = '';
    this.appendLog('system', 'Starting startup check and Darwin compatibility layer probe...');
    try {
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
      this.appendLog('system', `Parsing target IPA manifest: ${manifest.name} (${manifest.bundleId})`);

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
      await this.loadInstalledApps();
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
      this.appendLog('system', 'iOS runtime libraries ready, invoking dyld execution...');
      const result = await this.ensureRuntime().runDiagnostics(directory, `${appDirectory}/${manifest.executable}`,
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

      this.appendLog('system', `Execution finished: appExecuted=${verification.appExecuted}, dyldTraps=${result.dyldBootstrap.traps}`);

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
      const saved = `{"timestamp":${Date.now()},"gate0":{"raw":${JSON.stringify(result.rawProbe)},` +
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
      if (result.frameDiagnostics && !result.frameDiagnostics.includes('"totalFrames":0')) {
        this.rendererStatus = 'CoreAnimation rendering active (first frame generated)';
        this.appendLog('guest', 'CoreAnimation successfully rendered first frame');
      }
      for (let offset = 0; offset < saved.length; offset += 700) {
        hilog.info(0x484d, 'HarmoniosReport', '%{public}d %{public}s', offset, saved.substring(offset, offset + 700));
      }
      hilog.info(0x484d, 'Harmonios', 'Gate0 %{public}s; appExecuted=%{public}s',
        this.gate, String(report.appExecuted));
    } catch (error) {
      this.status = 'Check failed';
      this.details = `Check failed: ${String(error)}`;
      this.appendLog('system', `Execution error: ${String(error)}`);
      hilog.error(0x484d, 'Harmonios', 'Execution failed: %{public}s', String(error));
    } finally {
      this.busy = false;
    }
  }

  // --- Top Navigation Header (ArkUI Standard Style) ---
  @Builder
  private topHeader(title: string, subtitle?: string) {
    Row() {
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
          Text('Probing')
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
          Text('Darwin Ready')
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

  // --- Tab 0: Applications (Harmonios Launcher Catalog & Runner) ---
  @Builder
  private applicationsCatalogView() {
    Column() {
      // Header matching mockup
      Row() {
        Column({ space: 4 }) {
          Text($r('app.string.app_name'))
            .fontSize(24)
            .fontWeight(FontWeight.Bold)
            .fontColor($r('app.color.text_primary'))
          Text('Applications')
            .fontSize(14)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('app.color.text_secondary'))
        }
        .alignItems(HorizontalAlign.Start)

        Blank()

        Row({ space: 4 }) {
          SymbolGlyph($r('sys.symbol.checkmark_circle_fill'))
            .fontSize(14)
            .fontColor(['#34C759'])
          Text('Darwin Ready')
            .fontSize(12)
            .fontColor($r('app.color.text_secondary'))
        }
        .padding({ left: 8, right: 10, top: 4, bottom: 4 })
        .backgroundColor($r('app.color.card_background'))
        .borderRadius(12)
        .border({ width: 0.5, color: $r('app.color.border_subtle') })
      }
      .width('100%')
      .padding({ left: 16, right: 16, top: 12, bottom: 8 })

      List({ space: 12 }) {
        ForEach(this.appsList, (app: AppItem) => {
          ListItem() {
            Row({ space: 14 }) {
              // Real iOS App Icon
              Image(app.icon)
                .width(52)
                .height(52)
                .borderRadius(13)
                .objectFit(ImageFit.Cover)
                .shadow({ radius: 6, color: '#1A000000', offsetY: 2 })

              Column({ space: 4 }) {
                Text(app.name)
                  .fontSize(16)
                  .fontWeight(FontWeight.Bold)
                  .fontColor($r('app.color.text_primary'))
                Text(app.versionInfo)
                  .fontSize(10.5)
                  .lineHeight(15)
                  .fontColor($r('app.color.text_secondary'))
                  .wordBreak(WordBreak.BREAK_ALL)
                  .maxLines(2)
                  .textOverflow({ overflow: TextOverflow.Ellipsis })
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              Button({ type: ButtonType.Capsule, stateEffect: true }) {
                Text('Open')
                  .fontSize(13)
                  .fontWeight(FontWeight.Medium)
                  .fontColor(app.isRunnable ? $r('app.color.on_accent') : $r('app.color.text_tertiary'))
                  .padding({ left: 16, right: 16, top: 7, bottom: 7 })
              }
              .backgroundColor(app.isRunnable ? $r('app.color.accent') : $r('app.color.inset_background'))
              .enabled(app.isRunnable)
              .onClick(() => {
                if (app.isRunnable) {
                  hilog.info(0x484d, 'Harmonios', 'Opening app in Specified mode: %{public}s', app.bundleId);
                  const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
                  const want: Want = {
                    bundleName: 'fun.oboard.hamintosh',
                    abilityName: 'HarmoniosSpecifiedAbility',
                    moduleName: 'harmonios'
                  };
                  const params: Record<string, Object> = {
                    'bundleId': app.bundleId,
                    'appName': app.name
                  };
                  want.parameters = params;
                  context.startAbility(want);
                }
              })
            }
            .width('100%')
            .padding({ left: 14, right: 14, top: 12, bottom: 12 })
            .backgroundColor($r('app.color.card_background'))
            .borderRadius(16)
            .border({ width: 0.5, color: $r('app.color.border_subtle') })
            .shadow({ radius: 6, color: '#06000000', offsetY: 2 })
          }
        })

        // Install IPA (solid rounded rectangle button matching user's spec)
        ListItem() {
          Button({ type: ButtonType.Normal, stateEffect: true }) {
            Row({ space: 8 }) {
              SymbolGlyph($r('sys.symbol.plus'))
                .fontSize(16)
                .fontColor(['#FFFFFF'])
              Text('Install IPA')
                .fontSize(15)
                .fontWeight(FontWeight.Medium)
                .fontColor('#FFFFFF')
            }
            .width('100%')
            .height(50)
            .justifyContent(FlexAlign.Center)
          }
          .width('100%')
          .backgroundColor('#0A84FF')
          .borderRadius(14)
          .shadow({ radius: 8, color: '#330A84FF', offsetY: 3 })
          .onClick(() => {
            promptAction.showToast({
              message: 'Use Harmonios Converter to convert and install IPA packages',
              duration: 2500
            });
          })
        }
        .margin({ top: 8 })
      }
      .width('100%')
      .layoutWeight(1)
      .padding({ left: 16, right: 16, top: 8, bottom: 16 })
      .scrollBar(BarState.Off)
    }
    .width('100%')
    .height('100%')
  }

  @Builder
  private runningAppView() {
    Column() {
      // Top Navigation with Back Button
      Row() {
        Button({ type: ButtonType.Normal, stateEffect: true }) {
          Row({ space: 4 }) {
            SymbolGlyph($r('sys.symbol.chevron_left'))
              .fontSize(18)
              .fontColor([$r('app.color.accent')])
            Text($r('app.string.app_name'))
              .fontSize(16)
              .fontColor($r('app.color.accent'))
          }
        }
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.activeAppRunning = false;
        })

        Blank()

        Text(this.name)
          .fontSize(17)
          .fontWeight(FontWeight.Bold)
          .fontColor($r('app.color.text_primary'))

        Blank()

        Row({ space: 4 }) {
          SymbolGlyph($r('sys.symbol.checkmark_circle_fill'))
            .fontSize(14)
            .fontColor(['#34C759'])
          Text('Running')
            .fontSize(12)
            .fontColor('#34C759')
        }
        .padding({ left: 8, right: 10, top: 4, bottom: 4 })
        .backgroundColor('#1534C759')
        .borderRadius(12)
      }
      .width('100%')
      .height(56)
      .padding({ left: 16, right: 16 })

      // CoreAnimation XComponent Surface
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

        if (!this.rendererStatus.includes('Connected')) {
          Column({ space: 10 }) {
            LoadingProgress()
              .width(28)
              .height(28)
              .color($r('app.color.accent'))
            Text('Waiting for CoreAnimation frame buffer mount...')
              .fontSize(12)
              .fontColor($r('app.color.text_secondary'))
          }
        }
      }
      .width('100%')
      .borderRadius(14)
      .clip(true)
      .border({ width: 0.5, color: $r('app.color.border_subtle') })
      .layoutWeight(1)
      .margin({ left: 16, right: 16, bottom: 16 })
    }
    .width('100%')
    .height('100%')
  }

  @Builder
  private appsTab() {
    if (this.activeAppRunning) {
      this.runningAppView();
    } else {
      this.applicationsCatalogView();
    }
  }

  // --- Tab 1: Logs (Dark Terminal Console) ---
  @Builder
  private consoleTab() {
    Column() {
      this.topHeader('Logs', 'Darwin Compatibility Layer & Guest Console')

      // Filter Segmented Controls
      Row({ space: 8 }) {
        Button({ type: ButtonType.Capsule }) {
          Row({ space: 4 }) {
            Text('All Logs')
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
            Text('Guest Console')
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
            Text('System Logs')
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
              Text('No log output yet, tap the button below to execute')
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
            Text('Clear Logs')
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
            Text('Re-probe')
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
      this.topHeader('Settings')

      List({ space: 16 }) {
        // Group 1: Probe Gate Overview
        ListItem() {
          Column({ space: 8 }) {
            Text('Execution Gate & Verification')
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
            Text('Darwin Kernel Compatibility Report')
              .fontSize(13)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('app.color.text_secondary'))
              .margin({ left: 4 })

            Column({ space: 10 }) {
              Text(this.details || 'Waiting for diagnostic report...')
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
            Text('About & Specifications')
              .fontSize(13)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('app.color.text_secondary'))
              .margin({ left: 4 })

            Column() {
              Row() {
                Text('Version')
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
                Text('Architecture')
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
                Text('Report Status')
                  .fontSize(14)
                  .fontColor($r('app.color.text_primary'))
                Blank()
                Row({ space: 4 }) {
                  Text(this.reportPath ? 'Saved' : 'Pending')
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

  // --- Bottom Tab Item Builder ---
  @Builder
  private tabItemBuilder(title: string, symbol: Resource, index: number) {
    Column({ space: 3 }) {
      SymbolGlyph(symbol)
        .fontSize(22)
        .fontColor([this.currentTabIndex === index ? $r('app.color.accent') : $r('app.color.text_secondary')])
      Text(title)
        .fontSize(10)
        .fontWeight(this.currentTabIndex === index ? FontWeight.Medium : FontWeight.Normal)
        .fontColor(this.currentTabIndex === index ? $r('app.color.accent') : $r('app.color.text_secondary'))
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
  }

  build() {
    Navigation() {
      Stack({ alignContent: Alignment.Bottom }) {
        Tabs({ barPosition: BarPosition.End, controller: this.tabsController }) {
          TabContent() {
            this.appsTab()
          }

          TabContent() {
            this.settingsTab()
          }
        }
        .barHeight(0)
        .scrollable(false)
        .width('100%')
        .height('100%')
        .onChange((index: number) => {
          this.currentTabIndex = index;
        })

        // Floating Rounded-Corner Frosted-Glass Navigation Dock matching |🏠 Home | ⚙️ Settings|
        Row() {
          Row({ space: 8 }) {
            SymbolGlyph($r('sys.symbol.house_fill'))
              .fontSize(20)
              .fontColor([this.currentTabIndex === 0 ? '#34C759' : $r('app.color.text_secondary')])
            Text('Home')
              .fontSize(14)
              .fontWeight(this.currentTabIndex === 0 ? FontWeight.Bold : FontWeight.Normal)
              .fontColor(this.currentTabIndex === 0 ? '#34C759' : $r('app.color.text_secondary'))
          }
          .layoutWeight(1)
          .height('100%')
          .justifyContent(FlexAlign.Center)
          .onClick(() => {
            this.currentTabIndex = 0;
            this.tabsController.changeIndex(0);
          })

          Divider()
            .vertical(true)
            .height(20)
            .color('#33FFFFFF')

          Row({ space: 8 }) {
            SymbolGlyph($r('sys.symbol.gearshape_fill'))
              .fontSize(20)
              .fontColor([this.currentTabIndex === 1 ? '#34C759' : $r('app.color.text_secondary')])
            Text('Settings')
              .fontSize(14)
              .fontWeight(this.currentTabIndex === 1 ? FontWeight.Bold : FontWeight.Normal)
              .fontColor(this.currentTabIndex === 1 ? '#34C759' : $r('app.color.text_secondary'))
          }
          .layoutWeight(1)
          .height('100%')
          .justifyContent(FlexAlign.Center)
          .onClick(() => {
            this.currentTabIndex = 1;
            this.tabsController.changeIndex(1);
          })
        }
        .width('70%')
        .height(56)
        .margin({ bottom: 20 })
        .borderRadius(28)
        .backgroundBlurStyle(BlurStyle.Thin)
        .backgroundColor('#661A2228')
        .border({ width: 0.5, color: '#33FFFFFF' })
        .shadow({ radius: 16, color: '#33000000', offsetY: 6 })
      }
      .width('100%')
      .height('100%')
    }
    .titleMode(NavigationTitleMode.Mini)
    .hideTitleBar(true)
    .hideBackButton(true)
    .width('100%')
    .height('100%')
    .padding({ top: this.safeTop, bottom: this.safeBottom, left: this.safeLeft, right: this.safeRight })
    .backgroundColor($r('app.color.page_background'))
  }
}
