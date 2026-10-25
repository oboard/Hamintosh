import { common } from '@kit.AbilityKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';
import { hilog } from '@kit.PerformanceAnalysisKit';
import runtime, { ProbeResult } from 'libhamintosh.so';

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
  @State status: string = '准备运行环境';
  @State bridge: string = '等待检查';
  @State gate: string = '等待真机执行探针';
  @State details: string = '';
  @State reportPath: string = '';
  @State busy: boolean = false;

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
      return `${title}: 返回 ${value.value}`;
    }
    return `${title}: ${value.status} (errno ${value.errno}, signal ${value.signal})`;
  }

  private async run(): Promise<void> {
    if (this.busy) {
      return;
    }
    this.busy = true;
    this.status = '正在检查';
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
        hilog.info(0x484d, 'Hamintosh', '运行库文件尚未导入：%{public}s', String(error));
      }
      for (const relative of sysrootFiles) {
        if (relative.startsWith('/') || relative.split('/').includes('..')) {
          throw new Error('运行库清单包含无效路径');
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
      this.bridge = result.runtime;
      this.gate = [this.probeText('原始 ARM64 文件', result.rawProbe),
        this.probeText('Mach-O 文件', result.machoProbe),
        this.probeText('Mach-O → 签名 ELF', result.packagedProbe)].join('\n');
      this.gate += result.targetImage.status === 'mapped-awaiting-dyld' ?
        '\n目标 IPA：ARM64 映像已装载，等待动态链接' : `\n目标映像：${result.targetImage.status}`;
      this.gate += `\nDarwin 调用转接：${result.darwinProbe.status}（${result.darwinProbe.traps} 次）`;
      this.gate += `\nARM64e 指针认证：${result.pacProbe.status}`;
      this.gate += `\nDarwin 启动栈：${result.bootStackProbe.status}`;
      this.gate += `\nARM64e 指针重定位：${result.rebaseProbe.status}`;
      this.gate += `\nApple dyld：${result.dyldBootstrap.status}`;
      this.status = report.appExecuted ? '已启动' : '启动受阻';
      const image = report.image;
      let summary = `目标系统：iOS ${manifest.minimumOS}\n`;
      if (image) {
        summary += `架构：${image.architecture}\n依赖：${image.dependencies.length} 个动态库\n`;
        summary += `导入符号：${image.undefinedSymbols.length}\n入口：0x${image.entryFileOffset.toString(16)}\n`;
      }
      summary += '\n';
      if (report.missingFiles && report.missingFiles.length > 0) {
        summary += `缺少 iOS 运行库：\n${report.missingFiles.join('\n')}\n\n`;
      }
      if (report.blockers) {
        summary += `待实现：\n${report.blockers.join('\n')}\n`;
      }
      if (report.error) {
        summary += report.error;
      }
      this.details = summary;
      if (result.dyldBootstrap.message.length > 0) {
        this.details += `\n加载器消息：${result.dyldBootstrap.message}\n`;
      }
      this.reportPath = `${context.filesDir}/compat-report.json`;
      const saved = `{"gate0":{"raw":${JSON.stringify(result.rawProbe)},` +
        `"macho":${JSON.stringify(result.machoProbe)},"packaged":${JSON.stringify(result.packagedProbe)}},` +
        `"target":${JSON.stringify(manifest)},"targetImage":${JSON.stringify(result.targetImage)},` +
        `"darwinProbe":${JSON.stringify(result.darwinProbe)},"pacProbe":${JSON.stringify(result.pacProbe)},` +
        `"bootStackProbe":${JSON.stringify(result.bootStackProbe)},` +
        `"rebaseProbe":${JSON.stringify(result.rebaseProbe)},` +
        `"dyldBootstrap":${JSON.stringify(result.dyldBootstrap)},` +
        `"preflight":${result.compatReport}}`;
      this.write(this.reportPath, saved);
      // Chunk the diagnostic so it can be retrieved on phones without sandbox file access.
      for (let offset = 0; offset < saved.length; offset += 700) {
        hilog.info(0x484d, 'HamintoshReport', '%{public}d %{public}s', offset, saved.substring(offset, offset + 700));
      }
      hilog.info(0x484d, 'Hamintosh', 'Gate0 %{public}s; appExecuted=%{public}s',
        this.gate, String(report.appExecuted));
    } catch (error) {
      this.status = '检查失败';
      this.details = `检查未完成：${String(error)}\n如果尚未导入 IPA，请先运行 tools/prepare_ipa.py。`;
      hilog.error(0x484d, 'Hamintosh', '%{public}s', this.details);
    } finally {
      this.busy = false;
    }
  }

  build() {
    Scroll() {
      Column({ space: 20 }) {
        Column({ space: 6 }) {
          Text('果易通 · Hamintosh').fontColor('#101828').fontSize(28).fontWeight(FontWeight.Bold)
          Text('iOS 应用运行实验').fontSize(14).fontColor('#667085')
        }.alignItems(HorizontalAlign.Start).width('100%')

        Column({ space: 8 }) {
          Text(this.name).fontColor('#101828').fontSize(22).fontWeight(FontWeight.Medium)
          Text(this.bundleId).fontSize(12).fontColor('#667085')
          Text(this.status).fontSize(16).fontColor('#9A6700')
          Button(this.busy ? '检查中…' : '重新检查启动条件')
            .enabled(!this.busy)
            .onClick(() => this.run())
        }.alignItems(HorizontalAlign.Start).padding(20).width('100%').backgroundColor('#F2F4F7').borderRadius(16)

        Column({ space: 10 }) {
          Text('运行时连接').fontColor('#101828').fontSize(18).fontWeight(FontWeight.Medium)
          Text(this.bridge).fontColor('#101828').fontSize(15)
          Text('ARM64 执行探针').fontColor('#101828').fontSize(18).fontWeight(FontWeight.Medium).margin({ top: 8 })
          Text(this.gate).fontColor('#101828').fontSize(14).lineHeight(24)
        }.alignItems(HorizontalAlign.Start).width('100%')

        Column({ space: 10 }) {
          Text('启动报告').fontColor('#101828').fontSize(18).fontWeight(FontWeight.Medium)
          Text(this.details).fontColor('#101828').fontSize(13).lineHeight(22).copyOption(CopyOptions.InApp)
          Text(this.reportPath).fontSize(11).fontColor('#667085').copyOption(CopyOptions.InApp)
        }.alignItems(HorizontalAlign.Start).width('100%')
      }.padding({ left: 24, right: 24, top: 40, bottom: 40 }).width('100%')
    }.width('100%').height('100%').backgroundColor('#FFFFFF')
  }
}
