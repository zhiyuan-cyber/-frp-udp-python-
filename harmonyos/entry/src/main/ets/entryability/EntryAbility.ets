/**
 * EntryAbility.ets —— 应用入口
 */

import UIAbility from '@ohos.app.ability.UIAbility';
import window from '@ohos.window';
import hilog from '@ohos.hilog';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import Want from '@ohos.app.ability.Want';

const DOMAIN = 0x0001;
const TAG = 'FrpHelper';

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, TAG, 'onCreate');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, '加载首页失败: %{public}s', JSON.stringify(err));
        return;
      }
      // 沉浸式：内容延伸到状态栏，深色底更协调
      windowStage.getMainWindow().then((win) => {
        win.setWindowLayoutFullScreen(true).catch(() => {});
        win.setWindowSystemBarProperties({
          statusBarContentColor: '#E8EDF4',
          navigationBarContentColor: '#E8EDF4'
        }).catch(() => {});
      }).catch(() => {});
    });
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'onDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, TAG, 'onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, TAG, 'onBackground');
  }
}
