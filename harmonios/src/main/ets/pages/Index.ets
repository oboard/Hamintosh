import { common } from '@kit.AbilityKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';
import { hilog } from '@kit.PerformanceAnalysisKit';
import runtime, { ProbeResult, RuntimeVerificationResult } from 'libharmonios.so';

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

  build() {
    Scroll() {
      Column({ space: 20 }) {
        Column({ space: 6 }) {
          Text('Harmonios').fontColor('#101828').fontSize(28).fontWeight(FontWeight.Bold)
        }.alignItems(HorizontalAlign.Start).width('100%')

        Column({ space: 8 }) {
          Text(this.name).fontColor('#101828').fontSize(22).fontWeight(FontWeight.Medium)
          Text(this.bundleId).fontSize(12).fontColor('#667085')
          Text(this.status).fontSize(16).fontColor('#9A6700')
          Text(this.busy ? 'Compatibility layer is forwarding calls' : `This launch recorded ${this.dyldTraps} transitions`)
            .fontSize(13).fontColor('#667085')
          Progress({
            value: this.busy ? 0 : this.dyldTraps > 0 ? 1 : 0,
            total: 1,
            type: ProgressType.Linear
          }).style({
            strokeWidth: 8,
            strokeRadius: 4,
            enableSmoothEffect: true,
            enableScanEffect: this.busy
          }).width('100%').height(8)
          Text('The transition count depends on the actual execution path; this shows scan progress and the number recorded for this launch.')
            .fontSize(11).fontColor('#98A2B3')
          Button(this.busy ? 'Checking…' : 'Check Launch Conditions Again')
            .enabled(!this.busy)
            .onClick(() => this.run())
        }.alignItems(HorizontalAlign.Start).padding(20).width('100%').backgroundColor('#F2F4F7').borderRadius(16)

        Column({ space: 10 }) {
          Text('iOS Render Surface').fontColor('#101828').fontSize(18).fontWeight(FontWeight.Medium)
          Text(this.rendererStatus).fontColor('#667085').fontSize(12)
          XComponent({
            type: XComponentType.SURFACE,
            controller: this.renderController
          }).width('100%').height(360).backgroundColor('#101828')
            .onLoad(() => this.attachRenderSurface())
            .onDestroy(() => this.detachRenderSurface())
          Text('BGRA content is submitted only after the original CoreAnimation/IOSurface produces a frame; a black screen means the graphics chain has not been reached yet.')
            .fontColor('#98A2B3').fontSize(11)
        }.alignItems(HorizontalAlign.Start).width('100%')

        Column({ space: 10 }) {
          Text('Runtime Connection').fontColor('#101828').fontSize(18).fontWeight(FontWeight.Medium)
          Text(this.bridge).fontColor('#101828').fontSize(15)
          Text('ARM64 Execution Probes').fontColor('#101828').fontSize(18).fontWeight(FontWeight.Medium).margin({ top: 8 })
          Text(this.gate).fontColor('#101828').fontSize(14).lineHeight(24)
        }.alignItems(HorizontalAlign.Start).width('100%')

        Column({ space: 10 }) {
          Text('Launch Report').fontColor('#101828').fontSize(18).fontWeight(FontWeight.Medium)
          Text(this.details).fontColor('#101828').fontSize(13).lineHeight(22).copyOption(CopyOptions.InApp)
          Text(this.reportPath).fontSize(11).fontColor('#667085').copyOption(CopyOptions.InApp)
        }.alignItems(HorizontalAlign.Start).width('100%')
      }.padding({ left: 24, right: 24, top: 40, bottom: 40 }).width('100%')
    }.width('100%').height('100%').backgroundColor('#FFFFFF')
  }
}
