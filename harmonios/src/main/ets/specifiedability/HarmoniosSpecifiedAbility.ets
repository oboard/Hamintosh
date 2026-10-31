import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';

const DOMAIN = 0x484d;
const TAG = 'HarmoniosSpecified';

export default class HarmoniosSpecifiedAbility extends UIAbility {
  private mainWindow: window.Window | undefined = undefined;
  private readonly avoidAreaListener = (): void => { this.updateSafeArea(); };

  private updateSafeArea(): void {
    const mainWindow = this.mainWindow;
    if (!mainWindow) return;
    try {
      const system = mainWindow.getWindowAvoidArea(window.AvoidAreaType.TYPE_SYSTEM);
      const cutout = mainWindow.getWindowAvoidArea(window.AvoidAreaType.TYPE_CUTOUT);
      const navigation = mainWindow.getWindowAvoidArea(window.AvoidAreaType.TYPE_NAVIGATION_INDICATOR);
      const ui = mainWindow.getUIContext();
      AppStorage.setOrCreate('safeTop', ui.px2vp(Math.max(system.topRect.height, cutout.topRect.height)));
      AppStorage.setOrCreate('safeLeft', ui.px2vp(Math.max(system.leftRect.width, cutout.leftRect.width, navigation.leftRect.width)));
      AppStorage.setOrCreate('safeBottom', ui.px2vp(Math.max(system.bottomRect.height, cutout.bottomRect.height, navigation.bottomRect.height)));
      AppStorage.setOrCreate('safeRight', ui.px2vp(Math.max(system.rightRect.width, cutout.rightRect.width, navigation.rightRect.width)));
    } catch (error) {
      hilog.error(DOMAIN, TAG, 'Safe area update failed: %{public}s', String(error));
    }
  }
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onCreate: %{public}s', JSON.stringify(want.parameters));
    AppStorage.setOrCreate('currentAppWant', want);
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onDestroy');
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onNewWant: %{public}s', JSON.stringify(want.parameters));
    AppStorage.setOrCreate('currentAppWant', want);
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onWindowStageCreate');
    try {
      const mainWindow = windowStage.getMainWindowSync();
      this.mainWindow = mainWindow;
      mainWindow.on('avoidAreaChange', this.avoidAreaListener);
      mainWindow.setWindowKeepScreenOn(true).catch(() => {
        hilog.warn(DOMAIN, TAG, 'Could not keep the runtime window awake');
      });
      mainWindow.setWindowLayoutFullScreen(true).then(() => this.updateSafeArea());
      this.updateSafeArea();
    } catch (_) {}
    windowStage.loadContent('pages/AppRunner', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, 'Failed to load AppRunner: %{public}s', JSON.stringify(err));
        return;
      }
      hilog.info(DOMAIN, TAG, 'Succeeded in loading AppRunner.');
      this.updateSafeArea();
    });
  }

  onWindowStageDestroy(): void {
    this.mainWindow?.off('avoidAreaChange', this.avoidAreaListener);
    this.mainWindow = undefined;
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onWindowStageDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onBackground');
  }
}
