/**
 * ApiClient.ets —— 与电脑端通信的 HTTP 客户端
 *
 * 为什么用 @ohos.net.http 而不是 fetch？
 *   鸿蒙 NEXT 上 @ohos.net.http 是最稳定的原生网络能力，
 *   支持超时、明文 HTTP（需在 module.json5 声明 INTERNET 权限）。
 *
 * ★ 明文 HTTP 说明：
 *   电脑端的控制接口跑在局域网内、走 http://（非 https）。
 *   鸿蒙默认拦截明文流量，需在 module.json5 里配置 network 安全策略，
 *   或者在 App 内用 `http` 模块并确保目标可达。
 *   详见 Readme 的"网络配置"一节。
 */

import http from '@ohos.net.http';
import { ApiResult, StatsSnapshot, ConnItem, ServerInfo, RuleItem, RulesPayload, LogLine } from '../model/Models';

/** 电脑端地址配置（可在设置页修改并持久化） */
export interface Endpoint {
  host: string;
  port: number;
  token: string;
}

const TIMEOUT_MS = 8000;

export class ApiClient {
  private ep: Endpoint;

  constructor(ep: Endpoint) {
    this.ep = ep;
  }

  setEndpoint(ep: Endpoint): void {
    this.ep = ep;
  }

  getEndpoint(): Endpoint {
    return this.ep;
  }

  private url(path: string): string {
    return `http://${this.ep.host}:${this.ep.port}${path}`;
  }

  /** 统一的 GET，带令牌鉴权头 */
  private async get<T>(path: string): Promise<ApiResult<T>> {
    const req = http.createHttp();
    try {
      const resp = await req.request(this.url(path), {
        method: http.RequestMethod.GET,
        header: {
          'X-Frp-Token': this.ep.token,
          'Content-Type': 'application/json'
        },
        connectTimeout: TIMEOUT_MS,
        readTimeout: TIMEOUT_MS
      });
      return this.parse<T>(resp);
    } catch (e) {
      return { ok: false, error: `连接失败：${(e as Error).message}` };
    } finally {
      req.destroy();
    }
  }

  /** 统一的 POST */
  private async post<T>(path: string, body: object): Promise<ApiResult<T>> {
    const req = http.createHttp();
    try {
      const resp = await req.request(this.url(path), {
        method: http.RequestMethod.POST,
        header: {
          'X-Frp-Token': this.ep.token,
          'Content-Type': 'application/json'
        },
        extraData: JSON.stringify(body),
        connectTimeout: TIMEOUT_MS,
        readTimeout: TIMEOUT_MS
      });
      return this.parse<T>(resp);
    } catch (e) {
      return { ok: false, error: `连接失败：${(e as Error).message}` };
    } finally {
      req.destroy();
    }
  }

  private parse<T>(resp: http.HttpResponse): ApiResult<T> {
    if (resp.responseCode !== 200) {
      if (resp.responseCode === 401) {
        return { ok: false, error: '访问令牌不正确' };
      }
      return { ok: false, error: `服务端返回 ${resp.responseCode}` };
    }
    try {
      const text = resp.result as string;
      return JSON.parse(text) as ApiResult<T>;
    } catch (e) {
      return { ok: false, error: '返回内容无法解析' };
    }
  }

  /** 探测是否连通（用于"测试连接"按钮） */
  async ping(): Promise<ApiResult<string>> {
    return await this.get<string>('/api/ping');
  }

  async stats(): Promise<ApiResult<StatsSnapshot>> {
    return await this.get<StatsSnapshot>('/api/stats');
  }

  async connections(): Promise<ApiResult<ConnItem[]>> {
    return await this.get<ConnItem[]>('/api/connections');
  }

  async serverInfo(): Promise<ApiResult<ServerInfo>> {
    return await this.get<ServerInfo>('/api/server-info');
  }

  async rules(): Promise<ApiResult<RulesPayload>> {
    return await this.get<RulesPayload>('/api/rules');
  }

  /** 日志：level 为 ALL 时不过滤 */
  async logs(level: string, keyword: string, limit: number): Promise<ApiResult<LogLine[]>> {
    const q = `?level=${encodeURIComponent(level)}&keyword=${encodeURIComponent(keyword)}&limit=${limit}`;
    return await this.get<LogLine[]>('/api/logs' + q);
  }

  /** 启停：which = server / client，action = start / stop */
  async control(which: string, action: string): Promise<ApiResult<string>> {
    return await this.post<string>('/api/control', { which, action });
  }

  /** 规则增删 */
  async addRule(host: string, ports: string, action: string, note: string): Promise<ApiResult<string>> {
    return await this.post<string>('/api/rules/add', { host, ports, action, note });
  }

  async removeRule(index: number): Promise<ApiResult<string>> {
    return await this.post<string>('/api/rules/remove', { index });
  }

  /** 改某条规则的类型：action = allow（白名单）/ deny（黑名单） */
  async setRuleAction(index: number, action: string): Promise<ApiResult<string>> {
    return await this.post<string>('/api/rules/action', { index, action });
  }

  /** 默认策略（未命中任何规则时）：mode = blacklist（放行）/ whitelist（拒绝） */
  async setRuleMode(mode: string, enabled: boolean): Promise<ApiResult<string>> {
    return await this.post<string>('/api/rules/mode', { mode, enabled });
  }
}
