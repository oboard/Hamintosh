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

interface FrameDiagnostics {
  totalFrames?: number;
}

@Entry
@Component
struct AppRunner {
  @StorageLink('currentAppWant') @Watch('targetAppChanged') currentWant: Want = {};
  @State appName: string = 'SwiftUIHelloWorld';
  @State bundleId: string = 'devplaceholder.HDPAWPTN.SwiftUIHelloWorld';
  @State rendererStatus: string = 'Connecting';
  @State isRunning: boolean = true;
  @State frameVisible: boolean = false;

  @StorageLink('safeTop') @Watch('safeAreaChanged') safeTop: number = 0;
  @StorageLink('safeBottom') @Watch('safeAreaChanged') safeBottom: number = 0;
  @StorageLink('safeLeft') @Watch('safeAreaChanged') safeLeft: number = 0;
  @StorageLink('safeRight') @Watch('safeAreaChanged') safeRight: number = 0;

  private renderController: XComponentController = new XComponentController();
  private runtime?: RuntimeExports;
  private safeAreaChanged(): void {
    this.runtime?.setGuestSafeArea(this.safeTop, this.safeLeft, this.safeBottom, this.safeRight);
  }
  private launchStarted: boolean = false;
  private restartGeneration: number = 0;
  private framePolling: boolean = false;

  private targetAppChanged(): void {
    const parameters = this.currentWant?.parameters;
    const nextName = parameters?.appName ? String(parameters.appName) : this.appName;
    const nextBundle = parameters?.bundleId ? String(parameters.bundleId) : this.bundleId;
    this.appName = nextName;
    this.bundleId = nextBundle;
    const generation = ++this.restartGeneration;
    hilog.info(0x484d, 'AppRunner', 'Target launch requested for %{public}s (%{public}s); restarting guest',
      this.appName, this.bundleId);
    if (!this.launchStarted) return;
    this.launchStarted = false;
    this.rendererStatus = 'Restarting';
    this.ensureRuntime().cancelDiagnostics();
    setTimeout(() => {
      if (generation !== this.restartGeneration || this.launchStarted) return;
      this.launchStarted = true;
      this.runApp();
    }, 100);
  }

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
    hilog.info(0x484d, 'AppRunner', 'Vulkan preflight: %{public}s', this.ensureRuntime().vulkanPreflight());
    hilog.info(0x484d, 'AppRunner', 'Metal render probe: %{public}s', this.ensureRuntime().metalRenderProbe());
  }

  private async watchFrames(): Promise<void> {
    if (this.framePolling) return;
    this.framePolling = true;
    const runtime = this.ensureRuntime();
    runtime.resetFrameDiagnostics();
    try {
      for (let attempt = 0; attempt < 480 && !this.frameVisible; ++attempt) {
        await new Promise<void>((resolve) => setTimeout(() => resolve(), 500));
        try {
          const diagnostics = JSON.parse(runtime.getFrameDiagnostics()) as FrameDiagnostics;
          if ((diagnostics.totalFrames ?? 0) > 0) {
            this.frameVisible = true;
            this.rendererStatus = 'Connected';
          }
        } catch (_) {}
      }
    } finally {
      this.framePolling = false;
    }
  }

  private async runApp(): Promise<void> {
    this.frameVisible = false;
    this.rendererStatus = 'Starting guest';
    this.watchFrames();
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const directory = `${context.filesDir}/probes`;
      let manifest: TargetManifest | undefined = undefined;
      let packagedTarget = false;

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
        packagedTarget = true;
        const targetManifestBytes = await context.resourceManager.getRawFileContent('target/manifest.json');
        manifest = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(
          new Uint8Array(targetManifestBytes.buffer.slice(targetManifestBytes.byteOffset,
            targetManifestBytes.byteOffset + targetManifestBytes.byteLength))
        )) as TargetManifest;
      }

      const appDirectory = `${context.filesDir}/apps/${manifest.bundleDirectory}`;
      if (packagedTarget) {
        for (const relative of manifest.bundleFiles) {
          if (relative.startsWith('/') || relative.split('/').includes('..')) {
            throw new Error('Target bundle manifest contains an invalid path');
          }
          const path = `${appDirectory}/${relative}`;
          const parent = path.substring(0, path.lastIndexOf('/'));
          if (!fs.accessSync(parent)) {
            fs.mkdirSync(parent, true);
          }
          const bytes = await context.resourceManager.getRawFileContent(`target/bundle/${relative}`);
          const file = fs.openSync(path, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.TRUNC);
          try {
            fs.writeSync(file.fd, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
          } finally {
            fs.closeSync(file);
          }
        }
      }
      const sysrootDirectory = `${context.filesDir}/sysroot`;
      let packagedSysroot = true;
      let sysrootBytes: Uint8Array | undefined;
      try {
        sysrootBytes = await context.resourceManager.getRawFileContent('sysroot/manifest.json');
      } catch (_) {
        packagedSysroot = false;
      }
      if (packagedSysroot && sysrootBytes) {
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
      } else if (!fs.accessSync(sysrootDirectory)) {
        throw new Error('No packaged or previously staged sysroot is available');
      } else {
        hilog.info(0x484d, 'AppRunner', 'Reusing previously staged sysroot at %{public}s', sysrootDirectory);
      }
      const metalLibraryPath = `${sysrootDirectory}/System/Library/Frameworks/QuartzCore.framework/default.metallib`;
      hilog.info(0x484d, 'AppRunner', 'sysroot=%{public}s default.metallib exists=%{public}d', sysrootDirectory, fs.accessSync(metalLibraryPath) ? 1 : 0);
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
        `"caRendererProbe":${result.caRendererProbe || "{}"},` +
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
      this.rendererStatus = result.success ? 'Preparing guest' : `Failed: ${result.status}`;
      hilog.info(0x484d, 'AppRunner', 'attachRenderSurface: %{public}s (1272 x 2860)', result.status);
      if (result.success && !this.launchStarted) {
        this.launchStarted = true;
        this.ensureRuntime().setGuestSafeArea(this.safeTop, this.safeLeft, this.safeBottom, this.safeRight);
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
        .onTouch((event: TouchEvent) => {
          if (event) {
            const touch = (event.touches && event.touches.length > 0) ? event.touches[0] :
              (event.changedTouches && event.changedTouches.length > 0) ? event.changedTouches[0] : null;
            if (touch) {
              const handled = this.ensureRuntime().dispatchTouchEvent(event.type, touch.x, touch.y);
              hilog.info(0x484d, 'AppRunner', 'onTouch: type=%{public}d x=%{public}f y=%{public}f handled=%{public}d',
                event.type, touch.x, touch.y, handled ? 1 : 0);
            }
          }
        })
      if (!this.frameVisible) {
        Column({ space: 14 }) {
          LoadingProgress()
            .width(38)
            .height(38)
            .color('#5856D6')
          Text(`正在启动 ${this.appName}`)
            .fontSize(19)
            .fontWeight(FontWeight.Medium)
            .fontColor('#1C1C1E')
          Text(this.rendererStatus)
            .fontSize(13)
            .fontColor('#6E6E73')
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .backgroundColor('#F2F2F7')
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#000000')
  }
}
