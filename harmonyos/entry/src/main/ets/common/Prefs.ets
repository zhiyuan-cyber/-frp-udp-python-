/**
 * Prefs.ets —— 配置持久化
 *
 * 存"电脑端地址 / 端口 / 访问令牌"，下次打开 App 自动带上，
 * 省得每次手输。用鸿蒙的 preferences（轻量键值存储）。
 */

import preferences from '@ohos.data.preferences';
import common from '@ohos.app.ability.common';
import { Endpoint } from '../model/ApiClient';

const STORE_NAME = 'frp_helper_cfg';
const KEY_HOST = 'host';
const KEY_PORT = 'port';
const KEY_TOKEN = 'token';

const DEFAULT_ENDPOINT: Endpoint = {
  host: '192.168.1.100',
  port: 8899,
  token: ''
};

export class Prefs {
  private store: preferences.Preferences | null = null;

  async init(ctx: common.UIAbilityContext): Promise<void> {
    this.store = await preferences.getPreferences(ctx, STORE_NAME);
  }

  async load(): Promise<Endpoint> {
    if (!this.store) {
      return DEFAULT_ENDPOINT;
    }
    const host = await this.store.get(KEY_HOST, DEFAULT_ENDPOINT.host) as string;
    const port = await this.store.get(KEY_PORT, DEFAULT_ENDPOINT.port) as number;
    const token = await this.store.get(KEY_TOKEN, '') as string;
    return { host, port, token };
  }

  async save(ep: Endpoint): Promise<void> {
    if (!this.store) {
      return;
    }
    await this.store.put(KEY_HOST, ep.host);
    await this.store.put(KEY_PORT, ep.port);
    await this.store.put(KEY_TOKEN, ep.token);
    await this.store.flush();
  }
}
