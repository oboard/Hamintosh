import { AbilityConstant, Configuration, ConfigurationConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';

const DOMAIN = 0x0000;

export default class HarmoniosAbility extends UIAbility {
  private mainWindow: window.Window | undefined = undefined;
  private readonly avoidAreaListener = (): void => {
    this.updateSafeArea();
  };

  private updateSafeArea(): void {
    const mainWindow = this.mainWindow;
    if (!mainWindow) {
      return;
    }
    try {
      const system = mainWindow.getWindowAvoidArea(window.AvoidAreaType.TYPE_SYSTEM);
      const cutout = mainWindow.getWindowAvoidArea(window.AvoidAreaType.TYPE_CUTOUT);
      const navigation = mainWindow.getWindowAvoidArea(window.AvoidAreaType.TYPE_NAVIGATION_INDICATOR);
      const uiContext = mainWindow.getUIContext();
      AppStorage.setOrCreate('safeTop', uiContext.px2vp(Math.max(system.topRect.height, cutout.topRect.height)));
      AppStorage.setOrCreate('safeBottom', uiContext.px2vp(Math.max(system.bottomRect.height,
        cutout.bottomRect.height, navigation.bottomRect.height)));
      AppStorage.setOrCreate('safeLeft', uiContext.px2vp(Math.max(system.leftRect.width,
        cutout.leftRect.width, navigation.leftRect.width)));
      AppStorage.setOrCreate('safeRight', uiContext.px2vp(Math.max(system.rightRect.width,
        cutout.rightRect.width, navigation.rightRect.width)));
    } catch (error) {
      hilog.error(DOMAIN, 'HarmoniosWindow', 'Safe area update failed: %{public}s', String(error));
    }
  }

  private async updateSystemBars(colorMode?: number): Promise<void> {
    const mainWindow = this.mainWindow;
    if (!mainWindow) {
      return;
    }
    try {
      const mode = colorMode ?? this.context.resourceManager.getConfigurationSync().colorMode;
      const dark = mode === ConfigurationConstant.ColorMode.COLOR_MODE_DARK;
      const foreground = dark ? '#EDF5F7' : '#162C35';
      await mainWindow.setWindowSystemBarProperties({
        statusBarColor: '#00000000',
        navigationBarColor: '#00000000',
        statusBarContentColor: foreground,
        navigationBarContentColor: foreground
      });
    } catch (error) {
      hilog.error(DOMAIN, 'HarmoniosWindow', 'System bar update failed: %{public}s', String(error));
    }
  }

  onConfigurationUpdate(newConfig: Configuration): void {
    this.updateSystemBars(newConfig.colorMode);
    this.updateSafeArea();
  }

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onCreate');
  }

  onDestroy(): void {
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // Main window is created, set main page for this ability
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onWindowStageCreate');

    try {
      this.context.getApplicationContext().setColorMode(ConfigurationConstant.ColorMode.COLOR_MODE_NOT_SET);
      this.mainWindow = windowStage.getMainWindowSync();
      this.mainWindow.on('avoidAreaChange', this.avoidAreaListener);
    } catch (error) {
      hilog.error(DOMAIN, 'HarmoniosWindow', 'Window setup failed: %{public}s', String(error));
    }
    this.loadMainPage(windowStage);
  }

  private async loadMainPage(windowStage: window.WindowStage): Promise<void> {
    try {
      await this.mainWindow?.setWindowLayoutFullScreen(true);
      await this.updateSystemBars();
    } catch (error) {
      hilog.error(DOMAIN, 'HarmoniosWindow', 'Immersive layout failed: %{public}s', String(error));
    }
    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, 'testTag', 'Failed to load content: %{public}s', JSON.stringify(err));
        return;
      }
      this.updateSafeArea();
    });
  }

  onWindowStageDestroy(): void {
    this.mainWindow?.off('avoidAreaChange', this.avoidAreaListener);
    this.mainWindow = undefined;
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    this.updateSystemBars();
    this.updateSafeArea();
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onForeground');
  }

  onBackground(): void {
    // Ability has back to background
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onBackground');
  }
}