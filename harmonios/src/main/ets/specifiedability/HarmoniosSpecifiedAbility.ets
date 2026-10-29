import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';

const DOMAIN = 0x484d;
const TAG = 'HarmoniosSpecified';

export default class HarmoniosSpecifiedAbility extends UIAbility {
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
      mainWindow.setWindowKeepScreenOn(true).catch(() => {
        hilog.warn(DOMAIN, TAG, 'Could not keep the runtime window awake');
      });
      mainWindow.setWindowLayoutFullScreen(true);
    } catch (_) {}
    windowStage.loadContent('pages/AppRunner', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, 'Failed to load AppRunner: %{public}s', JSON.stringify(err));
        return;
      }
      hilog.info(DOMAIN, TAG, 'Succeeded in loading AppRunner.');
    });
  }

  onWindowStageDestroy(): void {
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onWindowStageDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, TAG, 'HarmoniosSpecifiedAbility onBackground');
  }
}
