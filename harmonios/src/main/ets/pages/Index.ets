import { common } from '@kit.AbilityKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';
import { hilog } from '@kit.PerformanceAnalysisKit';
import runtime, { ProbeResult } from 'libharmonios.so';

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
  @State bundleId: string = '';
  @State status: string = 'Preparing runtime';
  @State bridge: string = 'Waiting for check';
  @State gate: string = 'Waiting for on-device execution probe';
  @State details: string = '';
  @State reportPath: string = '';
  @State busy: boolean = false;
  @State dyldTraps: number = 0;
  @State rendererStatus: string = 'Waiting for XComponent surface';
  @State showDiagnostics: boolean = false;
  @StorageLink('safeTop') safeTop: number = 0;
  @StorageLink('safeBottom') safeBottom: number = 0;
  @StorageLink('safeLeft') safeLeft: number = 0;
  @StorageLink('safeRight') safeRight: number = 0;
  private renderController: XComponentController = new XComponentController();

  aboutToAppear(): void {
    this.run();
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
      this.rendererStatus = result.success ? 'NativeWindow connected; waiting for a CoreAnimation frame' :
        `NativeWindow connection failed: ${result.status}`;
      hilog.info(0x484d, 'HarmoniosRender', 'surface=%{public}s status=%{public}s',
        surfaceId, result.status);
    } catch (error) {
      this.rendererStatus = `NativeWindow connection failed: ${String(error)}`;
      hilog.error(0x484d, 'HarmoniosRender', '%{public}s', this.rendererStatus);
    }
  }

  private detachRenderSurface(): void {
    try {
      runtime.detachRenderSurface();
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
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const directory = `${context.filesDir}/probes`;
      if (!fs.accessSync(directory)) {
        fs.mkdirSync(directory, true);
      }
      const manifestBytes = await context.resourceManager.getRawFileContent('target/manifest.json');
      const decoder = new util.TextDecoder('utf-8');
      const manifest = JSON.parse(decoder.decodeToString(manifestBytes)) as TargetManifest;
      this.name = manifest.name;
      this.bundleId = manifest.bundleId;
      await this.copyResource(context, 'probes/execution_probe.bin', `${directory}/execution_probe.bin`);
      await this.copyResource(context, 'probes/return42.macho', `${directory}/return42.macho`);
      const appDirectory = `${context.filesDir}/apps/${manifest.bundleDirectory}`;
      for (const relative of manifest.bundleFiles) {
        const path = `${appDirectory}/${relative}`;
        const parent = path.substring(0, path.lastIndexOf('/'));
        if (!fs.accessSync(parent)) {
          fs.mkdirSync(parent, true);
        }
        await this.copyResource(context, `target/bundle/${relative}`, path);
      }
      const sysrootDirectory = `${context.filesDir}/sysroot`;
      if (!fs.accessSync(sysrootDirectory)) {
        fs.mkdirSync(sysrootDirectory, true);
      }
      let sysrootFiles: string[] = [];
      try {
        const sysrootBytes = await context.resourceManager.getRawFileContent('sysroot/manifest.json');
        const sysrootManifest = JSON.parse(decoder.decodeToString(sysrootBytes)) as SysrootManifest;
        sysrootFiles = sysrootManifest.files;
      } catch (error) {
        hilog.info(0x484d, 'Harmonios', 'Runtime library files have not been imported: %{public}s', String(error));
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
        `"preflight":${JSON.stringify(report)}}`;
      this.write(this.reportPath, saved);
      // Chunk the diagnostic so it can be retrieved on phones without sandbox file access.
      for (let offset = 0; offset < saved.length; offset += 700) {
        hilog.info(0x484d, 'HarmoniosReport', '%{public}d %{public}s', offset, saved.substring(offset, offset + 700));
      }
      hilog.info(0x484d, 'Harmonios', 'Gate0 %{public}s; appExecuted=%{public}s',
        this.gate, String(report.appExecuted));
    } catch (error) {
      this.status = 'Check failed';
      this.details = `Check did not complete: ${String(error)}\nIf the IPA has not been imported, run tools/prepare_ipa.py first.`;
      hilog.error(0x484d, 'Harmonios', '%{public}s', this.details);
    } finally {
      this.busy = false;
    }
  }

  private statusLabel(): string {
    if (this.busy) {
      return '正在检查';
    }
    if (this.status === 'Launched') {
      return '已启动';
    }
    return this.status === 'Check failed' ? '检查失败' : '等待就绪';
  }

  @Builder
  private sectionHeading(index: string, title: string, caption: string) {
    Row({ space: 10 }) {
      Text(index)
        .fontSize(11).fontWeight(FontWeight.Bold).fontColor($r('app.color.accent'))
        .width(28).height(28).textAlign(TextAlign.Center)
        .backgroundColor($r('app.color.accent_soft')).borderRadius(9)
      Column({ space: 3 }) {
        Text(title).fontSize(17).fontWeight(FontWeight.Bold).fontColor($r('app.color.text_primary'))
        Text(caption).fontSize(11).fontColor($r('app.color.text_secondary'))
      }.alignItems(HorizontalAlign.Start).layoutWeight(1)
    }.width('100%')
  }

  @Builder
  private metric(value: string, label: string) {
    Column({ space: 5 }) {
      Text(value).fontSize(22).fontWeight(FontWeight.Bold).fontColor($r('app.color.text_primary'))
      Text(label).fontSize(11).fontColor($r('app.color.text_secondary'))
    }.alignItems(HorizontalAlign.Start).layoutWeight(1)
  }

  build() {
    Column() {
      Scroll() {
        Column({ space: 18 }) {
          Row() {
            Row({ space: 10 }) {
              Text('H').fontSize(22).fontWeight(FontWeight.Bold)
                .fontColor($r('app.color.on_accent')).width(42).height(42)
                .textAlign(TextAlign.Center).backgroundColor($r('app.color.accent')).borderRadius(14)
              Column({ space: 2 }) {
                Text('Harmonios').fontSize(22).fontWeight(FontWeight.Bold)
                  .fontColor($r('app.color.text_primary'))
                Text('iOS 应用运行空间').fontSize(11).fontColor($r('app.color.text_secondary'))
              }.alignItems(HorizontalAlign.Start)
            }
            Blank()
            Text('工作台').fontSize(12).fontWeight(FontWeight.Medium)
              .fontColor($r('app.color.accent')).padding({ left: 12, right: 12, top: 7, bottom: 7 })
              .backgroundColor($r('app.color.accent_soft')).borderRadius(20)
          }.width('100%').margin({ bottom: 8 })

          Column({ space: 20 }) {
            Row() {
              Text('当前应用 / CURRENT APP').fontSize(10).fontWeight(FontWeight.Bold)
                .fontColor($r('app.color.text_secondary')).letterSpacing(1)
              Blank()
              Row({ space: 5 }) {
                if (this.busy) {
                  LoadingProgress().width(14).height(14).color($r('app.color.accent'))
                }
                Text(this.statusLabel()).fontSize(11).fontWeight(FontWeight.Medium)
                  .fontColor(this.busy || this.status === 'Launched' ?
                    $r('app.color.accent') : $r('app.color.warning'))
              }.padding({ left: 10, right: 10, top: 6, bottom: 6 })
                .backgroundColor(this.busy || this.status === 'Launched' ?
                  $r('app.color.accent_soft') : $r('app.color.warning_soft')).borderRadius(20)
            }.width('100%')
            Column({ space: 7 }) {
              Text(this.name).fontSize(27).fontWeight(FontWeight.Bold)
                .fontColor($r('app.color.text_primary')).wordBreak(WordBreak.BREAK_ALL)
              Text(this.bundleId || '正在读取应用信息…').fontSize(12)
                .fontColor($r('app.color.text_secondary')).wordBreak(WordBreak.BREAK_ALL)
            }.width('100%').alignItems(HorizontalAlign.Start)
            Row() {
              this.metric('ARM64', '目标架构')
              this.metric(this.dyldTraps.toString(), '本次 dyld 转换')
              this.metric('iOS', '兼容运行环境')
            }.width('100%').padding(16).backgroundColor($r('app.color.inset_background')).borderRadius(16)
            Text(this.busy ? '正在验证执行路径并连接兼容运行环境…' :
              this.status === 'Launched' ? '应用入口已执行，可查看下方渲染画面。' :
                this.status === 'Check failed' ? '检查未完成，展开诊断详情查看错误。' :
                  '应用尚未启动，展开诊断详情查看缺失依赖与阻塞原因。')
              .fontSize(12).lineHeight(19).fontColor($r('app.color.text_secondary')).width('100%')
            Button(this.busy ? '正在检查启动条件…' : '重新检查启动条件', { type: ButtonType.Normal })
              .width('100%').height(48).borderRadius(14).fontSize(14).fontWeight(FontWeight.Medium)
              .fontColor($r('app.color.on_accent')).backgroundColor($r('app.color.accent'))
              .enabled(!this.busy).opacity(this.busy ? 0.65 : 1).onClick(() => this.run())
          }.alignItems(HorizontalAlign.Start).padding(20).width('100%')
            .backgroundColor($r('app.color.card_background')).borderRadius(24)

          Column({ space: 16 }) {
            this.sectionHeading('01', '应用画面', '来自 iOS CoreAnimation 的原生渲染')
            Stack({ alignContent: Alignment.TopStart }) {
              XComponent({
                type: XComponentType.SURFACE,
                controller: this.renderController
              }).width('100%').aspectRatio(9 / 16).backgroundColor('#000000')
                .onLoad(() => this.attachRenderSurface())
                .onDestroy(() => this.detachRenderSurface())
            }.width('100%').constraintSize({ maxWidth: 360 }).borderRadius(20).clip(true)
            Row({ space: 7 }) {
              Text('●').fontSize(8).fontColor($r('app.color.text_tertiary'))
              Text(this.rendererStatus).fontSize(11).lineHeight(17)
                .fontColor($r('app.color.text_secondary')).layoutWeight(1)
            }.width('100%')
            Text('收到首帧后将显示应用画面。黑屏表示图形链路尚未产生可显示的帧。')
              .fontSize(11).lineHeight(18).fontColor($r('app.color.text_tertiary')).width('100%')
          }.alignItems(HorizontalAlign.Center).padding(20).width('100%')
            .backgroundColor($r('app.color.card_background')).borderRadius(24)

          Column({ space: 16 }) {
            Row({ space: 12 }) {
              Column() {
                this.sectionHeading('02', '运行诊断', '执行探针、运行连接与启动报告')
              }.layoutWeight(1)
              Button(this.showDiagnostics ? '收起' : '展开', { type: ButtonType.Normal })
                .fontSize(12).height(36).padding({ left: 12, right: 12 }).borderRadius(12)
                .backgroundColor($r('app.color.accent_soft')).fontColor($r('app.color.accent'))
                .onClick(() => this.showDiagnostics = !this.showDiagnostics)
            }.width('100%')
            if (this.showDiagnostics) {
              Divider().color($r('app.color.border_subtle'))
              Text('运行连接').fontSize(13).fontWeight(FontWeight.Bold).fontColor($r('app.color.text_primary'))
              Text(this.bridge).fontSize(12).lineHeight(20).fontColor($r('app.color.text_secondary'))
                .copyOption(CopyOptions.InApp)
              Text('ARM64 执行探针').fontSize(13).fontWeight(FontWeight.Bold)
                .fontColor($r('app.color.text_primary'))
              Text(this.gate).fontSize(12).lineHeight(22).fontFamily('monospace')
                .fontColor($r('app.color.text_secondary')).copyOption(CopyOptions.InApp)
              Divider().color($r('app.color.border_subtle'))
              Text('启动报告').fontSize(13).fontWeight(FontWeight.Bold).fontColor($r('app.color.text_primary'))
              Text(this.details || '正在生成诊断报告…').fontSize(12).lineHeight(22)
                .fontColor($r('app.color.text_secondary')).copyOption(CopyOptions.InApp)
              if (this.reportPath.length > 0) {
                Text(this.reportPath).fontSize(10).lineHeight(17).wordBreak(WordBreak.BREAK_ALL)
                  .fontColor($r('app.color.text_tertiary')).copyOption(CopyOptions.InApp)
              }
            }
          }.alignItems(HorizontalAlign.Start).padding(20).width('100%')
            .backgroundColor($r('app.color.card_background')).borderRadius(24)
          Text('HARMONIOS  /  原生连接，无限可能').fontSize(9).letterSpacing(1)
            .fontColor($r('app.color.text_tertiary')).margin({ top: 6, bottom: 8 })
        }.width('100%').constraintSize({ maxWidth: 720 })
          .padding({ left: 20, right: 20, top: 24, bottom: 24 })
      }.width('100%').layoutWeight(1).scrollBar(BarState.Off)
    }.width('100%').height('100%')
      .padding({ top: this.safeTop, bottom: this.safeBottom, left: this.safeLeft, right: this.safeRight })
      .backgroundColor($r('app.color.page_background'))
  }
}
