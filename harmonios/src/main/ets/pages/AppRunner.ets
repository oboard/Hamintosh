import { common, Want } from '@kit.AbilityKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { uiMaterial } from '@kit.ArkUI';
import { loadRuntime, RuntimeExports } from 'libhm_load_probe.so';
import { cacheLibraryName } from 'ioscache';

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

@Entry
@Component
struct AppRunner {
  @StorageLink('currentAppWant') currentWant: Want = {};
  @State appName: string = 'SwiftUIHelloWorld';
  @State bundleId: string = 'devplaceholder.HDPAWPTN.SwiftUIHelloWorld';
  @State rendererStatus: string = 'Connecting';
  @State isRunning: boolean = true;

  @StorageLink('safeTop') safeTop: number = 0;
  @StorageLink('safeBottom') safeBottom: number = 0;
  @StorageLink('safeLeft') safeLeft: number = 0;
  @StorageLink('safeRight') safeRight: number = 0;

  private renderController: XComponentController = new XComponentController();
  private runtime?: RuntimeExports;
  private launchStarted: boolean = false;

  private ensureRuntime(): RuntimeExports {
    if (!this.runtime) {
      this.runtime = loadRuntime(cacheLibraryName);
    }
    return this.runtime;
  }

  aboutToAppear(): void {
    if (this.currentWant?.parameters?.appName) {
      this.appName = String(this.currentWant.parameters.appName);
    }
    if (this.currentWant?.parameters?.bundleId) {
      this.bundleId = String(this.currentWant.parameters.bundleId);
    }
    hilog.info(0x484d, 'AppRunner', 'Launching %{public}s (%{public}s)', this.appName, this.bundleId);
  }

  private async runApp(): Promise<void> {
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const directory = `${context.filesDir}/probes`;
      let manifest: TargetManifest | undefined = undefined;

      const appsDir = `${context.filesDir}/apps`;
      if (fs.accessSync(appsDir)) {
        const entries = fs.listFileSync(appsDir);
        for (const entry of entries) {
          const manifestPath = `${appsDir}/${entry}/manifest.json`;
          if (fs.accessSync(manifestPath)) {
            try {
              const content = fs.readTextSync(manifestPath);
              const extra = JSON.parse(content) as TargetManifest;
              if (extra.bundleId === this.bundleId || entry === `${this.appName}.app` || extra.name === this.appName) {
                manifest = extra;
                if (!manifest.bundleDirectory) {
                  manifest.bundleDirectory = entry;
                }
                break;
              }
            } catch (_) {}
          }
        }
      }

      if (!manifest) {
        const targetManifestBytes = await context.resourceManager.getRawFileContent('target/manifest.json');
        manifest = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(
          new Uint8Array(targetManifestBytes.buffer.slice(targetManifestBytes.byteOffset,
            targetManifestBytes.byteOffset + targetManifestBytes.byteLength))
        )) as TargetManifest;
      }

      const appDirectory = `${context.filesDir}/apps/${manifest.bundleDirectory}`;
      const sysrootDirectory = `${context.filesDir}/sysroot`;
      // Direct launches must refresh the same packaged sysroot as the home
      // screen, including resources added after the first installation.
      const sysrootBytes = await context.resourceManager.getRawFileContent('sysroot/manifest.json');
      const sysrootManifest = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(
        new Uint8Array(sysrootBytes.buffer.slice(sysrootBytes.byteOffset,
          sysrootBytes.byteOffset + sysrootBytes.byteLength))
      )) as SysrootManifest;
      if (!fs.accessSync(sysrootDirectory)) {
        fs.mkdirSync(sysrootDirectory, true);
      }
      for (const relative of sysrootManifest.files) {
        if (relative.startsWith('/') || relative.split('/').includes('..')) {
          throw new Error('Runtime library manifest contains an invalid path');
        }
        const path = `${sysrootDirectory}/${relative}`;
        const parent = path.substring(0, path.lastIndexOf('/'));
        if (!fs.accessSync(parent)) {
          fs.mkdirSync(parent, true);
        }
        const bytes = await context.resourceManager.getRawFileContent(`sysroot/${relative}`);
        const file = fs.openSync(path, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.TRUNC);
        try {
          fs.writeSync(file.fd, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
        } finally {
          fs.closeSync(file);
        }
      }
      hilog.info(0x484d, 'AppRunner', 'Starting iOS Userspace execution for %{public}s (%{public}s)', manifest.name, manifest.bundleId);
      const result = await this.ensureRuntime().runDiagnostics(directory, `${appDirectory}/${manifest.executable}`, sysrootDirectory);
      const reportPath = `${context.filesDir}/compat-report.json`;
      const saved = `{"timestamp":${Date.now()},` +
        `"target":${JSON.stringify(manifest)},"targetImage":${JSON.stringify(result.targetImage)},` +
        `"darwinProbe":${JSON.stringify(result.darwinProbe)},"pacProbe":${JSON.stringify(result.pacProbe)},` +
        `"bootStackProbe":${JSON.stringify(result.bootStackProbe)},` +
        `"rebaseProbe":${JSON.stringify(result.rebaseProbe)},` +
        `"dyldBootstrap":${JSON.stringify(result.dyldBootstrap)},` +
        `"runtimeVerification":${JSON.stringify(result.runtimeVerification)},` +
        `"frameDiagnostics":${result.frameDiagnostics || "{}"}}`;
      try {
        const file = fs.openSync(reportPath, fs.OpenMode.CREATE | fs.OpenMode.WRITE_ONLY | fs.OpenMode.TRUNC);
        fs.writeSync(file.fd, saved);
        fs.closeSync(file);
      } catch (_) {}
      for (let offset = 0; offset < saved.length; offset += 700) {
        hilog.info(0x484d, 'HarmoniosReport', '%{public}d %{public}s', offset, saved.substring(offset, offset + 700));
      }
    } catch (e) {
      hilog.error(0x484d, 'AppRunner', 'runApp error: %{public}s', String(e));
    }
  }

  private attachRenderSurface(): void {
    try {
      const surfaceId = this.renderController.getXComponentSurfaceId();
      const result = this.ensureRuntime().attachRenderSurface(surfaceId, 1272, 2860);
      this.rendererStatus = result.success ? 'Connected' : `Failed: ${result.status}`;
      hilog.info(0x484d, 'AppRunner', 'attachRenderSurface: %{public}s (1272 x 2860)', result.status);
      if (result.success && !this.launchStarted) {
        this.launchStarted = true;
        this.runApp();
      }
    } catch (e) {
      this.rendererStatus = `Error: ${String(e)}`;
      hilog.error(0x484d, 'AppRunner', 'attach error: %{public}s', String(e));
    }
  }

  private detachRenderSurface(): void {
    try {
      this.ensureRuntime().detachRenderSurface();
    } catch (_) {}
  }

  build() {
    Stack({ alignContent: Alignment.Center }) {
      XComponent({
        type: XComponentType.SURFACE,
        controller: this.renderController
      })
        .width('100%')
        .height('100%')
        .onLoad(() => this.attachRenderSurface())
        .onDestroy(() => this.detachRenderSurface())
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#000000')
  }
}
