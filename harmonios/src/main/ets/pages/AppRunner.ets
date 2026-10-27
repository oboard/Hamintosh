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
      const targetManifestBytes = await context.resourceManager.getRawFileContent('target/manifest.json');
      const manifest = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(
        new Uint8Array(targetManifestBytes.buffer.slice(targetManifestBytes.byteOffset,
          targetManifestBytes.byteOffset + targetManifestBytes.byteLength))
      )) as TargetManifest;
      const appDirectory = `${context.filesDir}/apps/${manifest.bundleDirectory}`;
      const sysrootDirectory = `${context.filesDir}/sysroot`;
      hilog.info(0x484d, 'AppRunner', 'Starting iOS Userspace execution for %{public}s', manifest.name);
      await this.ensureRuntime().runDiagnostics(directory, `${appDirectory}/${manifest.executable}`, sysrootDirectory);
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
      if (result.success) {
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
