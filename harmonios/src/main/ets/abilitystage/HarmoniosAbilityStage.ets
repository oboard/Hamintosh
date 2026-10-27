import { AbilityStage, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

const TAG = 'HarmoniosAbilityStage';
const DOMAIN = 0x484d;

export default class HarmoniosAbilityStage extends AbilityStage {
  onAcceptWant(want: Want): string {
    if (want.abilityName === 'HarmoniosSpecifiedAbility') {
      AppStorage.setOrCreate('wantParams', want.parameters);
      if (want.parameters?.bundleId !== undefined) {
        const bundleId = String(want.parameters.bundleId);
        hilog.info(DOMAIN, TAG, 'onAcceptWant instance: %{public}s', bundleId);
        return `HarmoniosInstance_${bundleId}`;
      }
      return 'HarmoniosInstance_default';
    }
    return '';
  }
}
