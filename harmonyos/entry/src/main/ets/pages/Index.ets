/**
 * Index.ets —— 主界面
 *
 * 五个标签页：
 *   首页   状态 / 流量 / 服务器信息 / 启停
 *   连接   当前正在使用隧道的连接列表
 *   日志   最近 7 天日志，级别筛选 + 关键字搜索
 *   规则   转发过滤规则（增删 + 黑白名单切换）
 *   设置   电脑端地址 / 端口 / 访问令牌
 *
 * 设计原则：
 *   · 所有网络请求都在 aboutToAppear 起的定时器里刷新，失败只在顶部提示，
 *     绝不弹模态框打断用户（移动端频繁弹窗很烦）。
 *   · 页面切换用 Tabs，不销毁状态，切回来立即有数据。
 */

import { ApiClient, Endpoint } from '../model/ApiClient';
import { StatsSnapshot, ConnItem, ServerInfo, RuleItem, RulesPayload, LogLine, ApiResult } from '../model/Models';
import { Prefs } from '../common/Prefs';
import { fmtBytes, fmtSpeed, fmtDuration, levelColor, runningColor, LOG_LEVELS } from '../common/Fmt';
import common from '@ohos.app.ability.common';
import promptAction from '@ohos.promptAction';

const DEFAULT_STATS: StatsSnapshot = {
  role: 'idle', running: false, uptime: 0, clients: 0, tunnels: 0,
  connections: 0, connectionsPeak: 0, bytesUp: 0, bytesDown: 0,
  speedUp: 0, speedDown: 0, rejected: 0, authFailed: 0
};

const DEFAULT_INFO: ServerInfo = {
  publicIp: '-', geo: '-', isp: '-', latencyMs: 0, localPorts: []
};

@Entry
@Component
struct Index {
  @State tabIndex: number = 0;
  @State connected: boolean = false;
  @State statusText: string = '未连接';
  @State stats: StatsSnapshot = DEFAULT_STATS;
  @State conns: ConnItem[] = [];
  @State info: ServerInfo = DEFAULT_INFO;
  @State rules: RulesPayload = { mode: 'blacklist', enabled: true, rules: [] };
  @State logs: LogLine[] = [];
  @State logLevel: string = 'ALL';
  @State logKeyword: string = '';
  @State busy: boolean = false;

  // 规则页：新增规则表单（类型默认黑名单 —— 加规则的本意多半是"拦掉"）
  @State newRuleHost: string = '*';
  @State newRulePorts: string = '';
  @State newRuleNote: string = '';
  @State newRuleAction: string = 'deny';

  // 设置页字段
  @State host: string = '';
  @State port: string = '';
  @State token: string = '';

  private api: ApiClient = new ApiClient({ host: '', port: 0, token: '' });
  private prefs: Prefs = new Prefs();
  private timerId: number = -1;
  private pageReady: boolean = false;

  async aboutToAppear(): Promise<void> {
    const ctx = getContext(this) as common.UIAbilityContext;
    await this.prefs.init(ctx);
    const ep = await this.prefs.load();
    this.host = ep.host;
    this.port = `${ep.port}`;
    this.token = ep.token;
    this.api.setEndpoint(ep);
    this.pageReady = true;
    await this.refreshAll();
    this.startTimer();
  }

  aboutToDisappear(): void {
    this.stopTimer();
  }

  onPageShow(): void {
    if (this.pageReady) {
      this.startTimer();
    }
  }

  onPageHide(): void {
    this.stopTimer();
  }

  private startTimer(): void {
    this.stopTimer();
    // 每 2 秒刷一次状态；日志与连接跟着一起刷
    this.timerId = setInterval(() => {
      this.refreshAll();
    }, 2000);
  }

  private stopTimer(): void {
    if (this.timerId !== -1) {
      clearInterval(this.timerId);
      this.timerId = -1;
    }
  }

  /** 统一刷新：任何一项失败都视为断线，但不清空已有数据 */
  private async refreshAll(): Promise<void> {
    const r: ApiResult<StatsSnapshot> = await this.api.stats();
    if (!r.ok || !r.data) {
      this.connected = false;
      this.statusText = r.error ?? '连接失败';
      return;
    }
    this.connected = true;
    this.stats = r.data;
    this.statusText = r.data.running ? '运行中' : '已连接 · 未运行';

    const c = await this.api.connections();
    if (c.ok && c.data) {
      this.conns = c.data;
    }
    // 日志只在日志页刷新，省流量
    if (this.tabIndex === 2) {
      await this.loadLogs();
    }
  }

  private async loadLogs(): Promise<void> {
    const r = await this.api.logs(this.logLevel, this.logKeyword, 400);
    if (r.ok && r.data) {
      this.logs = r.data;
    }
  }

  private async loadServerInfo(): Promise<void> {
    const r = await this.api.serverInfo();
    if (r.ok && r.data) {
      this.info = r.data;
    } else {
      promptAction.showToast({ message: r.error ?? '获取服务器信息失败' });
    }
  }

  private async loadRules(): Promise<void> {
    const r = await this.api.rules();
    if (r.ok && r.data) {
      this.rules = r.data;
    } else {
      promptAction.showToast({ message: r.error ?? '获取规则失败' });
    }
  }

  private async doControl(which: string, action: string): Promise<void> {
    if (this.busy) {
      return;
    }
    this.busy = true;
    const r = await this.api.control(which, action);
    this.busy = false;
    promptAction.showToast({ message: r.ok ? (r.data ?? '已执行') : (r.error ?? '失败') });
    await this.refreshAll();
  }

  private async saveSettings(): Promise<void> {
    const p = parseInt(this.port, 10);
    if (!this.host.trim() || isNaN(p) || p < 1 || p > 65535) {
      promptAction.showToast({ message: '请填写正确的地址与端口（1-65535）' });
      return;
    }
    const ep: Endpoint = { host: this.host.trim(), port: p, token: this.token.trim() };
    this.api.setEndpoint(ep);
    await this.prefs.save(ep);
    const ping = await this.api.ping();
    if (ping.ok) {
      promptAction.showToast({ message: '连接成功，配置已保存' });
      await this.refreshAll();
    } else {
      promptAction.showToast({ message: `保存成功，但连接失败：${ping.error}` });
    }
  }

  // ================= 渲染 =================

  build() {
    Column() {
      this.TopBar()

      Tabs({ barPosition: BarPosition.End, index: this.tabIndex }) {
        TabContent() { this.HomePage() }
        .tabBar(this.TabItem('首页', 0))

        TabContent() { this.ConnPage() }
        .tabBar(this.TabItem('连接', 1))

        TabContent() { this.LogPage() }
        .tabBar(this.TabItem('日志', 2))

        TabContent() { this.RulePage() }
        .tabBar(this.TabItem('规则', 3))

        TabContent() { this.SettingPage() }
        .tabBar(this.TabItem('设置', 4))
      }
      .barHeight(58)
      .barBackgroundColor('#161C24')
      .onChange((i: number) => {
        this.tabIndex = i;
        if (i === 2) {
          this.loadLogs();
        } else if (i === 3) {
          this.loadRules();
        } else if (i === 0) {
          this.loadServerInfo();
        }
      })
      .layoutWeight(1)
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#101418')
  }

  @Builder
  TopBar() {
    Row() {
      Text('内网穿透助手')
        .fontSize(18)
        .fontWeight(FontWeight.Bold)
        .fontColor('#E8EDF4')
      Blank()
      Row() {
        Circle({ width: 8, height: 8 })
          .fill(this.connected ? '#3FBF7F' : '#FF7B72')
        Text(this.connected ? this.statusText : '未连接')
          .fontSize(12)
          .fontColor(this.connected ? '#3FBF7F' : '#FF7B72')
          .margin({ left: 6 })
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
      }
      .constraintSize({ maxWidth: 170 })
    }
    .width('100%')
    .height(56)
    .padding({ left: 18, right: 18, top: 8 })
    .backgroundColor('#161C24')
  }

  @Builder
  TabItem(label: string, idx: number) {
    Column() {
      Text(label)
        .fontSize(12)
        .fontColor(this.tabIndex === idx ? '#4C8DFF' : '#6B7785')
        .fontWeight(this.tabIndex === idx ? FontWeight.Bold : FontWeight.Normal)
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
  }

  // ============ 首页 ============
  @Builder
  HomePage() {
    Scroll() {
      Column() {
        // 状态 + 启停
        Column() {
          Row() {
            Column() {
              Text(this.stats.running ? '正在运行' : '未运行')
                .fontSize(17)
                .fontWeight(FontWeight.Bold)
                .fontColor(runningColor(this.stats.running))
              Text(this.stats.role === 'server' ? '服务端' :
                (this.stats.role === 'client' ? '客户端' : '空闲'))
                .fontSize(12)
                .fontColor('#9AA7B8')
                .margin({ top: 4 })
            }
            .alignItems(HorizontalAlign.Start)

            Blank()

            Button(this.stats.running && this.stats.role === 'server' ? '停止服务端' : '启动服务端')
              .fontSize(13)
              .height(38)
              .backgroundColor(this.stats.running && this.stats.role === 'server' ? '#3A2A2A' : '#22303F')
              .fontColor(this.stats.running && this.stats.role === 'server' ? '#FF7B72' : '#4C8DFF')
              .enabled(!this.busy)
              .onClick(() => {
                const isRunning = this.stats.running && this.stats.role === 'server';
                this.doControl('server', isRunning ? 'stop' : 'start');
              })
          }
          .width('100%')

          Row() {
            Blank()
            Button('启动客户端')
              .fontSize(13)
              .height(34)
              .backgroundColor('#22303F')
              .fontColor('#4C8DFF')
              .enabled(!this.busy)
              .onClick(() => this.doControl('client', 'start'))
            Button('停止客户端')
              .fontSize(13)
              .height(34)
              .margin({ left: 10 })
              .backgroundColor('#2A333F')
              .fontColor('#9AA7B8')
              .enabled(!this.busy)
              .onClick(() => this.doControl('client', 'stop'))
          }
          .width('100%')
          .margin({ top: 12 })
        }
        .width('100%')
        .padding(16)
        .backgroundColor('#1A2028')
        .borderRadius(14)
        .border({ width: 1, color: '#2A333F' })

        // 流量指标
        Column() {
          Text('实时流量')
            .fontSize(16)
            .fontWeight(FontWeight.Bold)
            .fontColor('#E8EDF4')
            .margin({ bottom: 6 })

          Row() {
            this.Tile('上行速度', fmtSpeed(this.stats.speedUp), '', '#4C8DFF')
            this.Tile('下行速度', fmtSpeed(this.stats.speedDown), '', '#3FBF7F')
          }
          .width('100%')

          Row() {
            this.Tile('累计上行', fmtBytes(this.stats.bytesUp), '', '#E8EDF4')
            this.Tile('累计下行', fmtBytes(this.stats.bytesDown), '', '#E8EDF4')
          }
          .width('100%')

          Row() {
            this.Tile('活跃连接', `${this.stats.connections}`, `峰值 ${this.stats.connectionsPeak}`, '#E8EDF4')
            this.Tile('在线客户端', `${this.stats.clients}`, `隧道 ${this.stats.tunnels}`, '#E8EDF4')
          }
          .width('100%')

          Row() {
            this.Tile('运行时长', fmtDuration(this.stats.uptime), '', '#9AA7B8')
            this.Tile('拒绝/鉴权失败', `${this.stats.rejected}/${this.stats.authFailed}`, '', '#E3B341')
          }
          .width('100%')
        }
        .width('100%')
        .padding(16)
        .margin({ top: 12 })
        .backgroundColor('#1A2028')
        .borderRadius(14)
        .border({ width: 1, color: '#2A333F' })

        // 服务器信息
        Column() {
          Row() {
            Text('服务器信息')
              .fontSize(16)
              .fontWeight(FontWeight.Bold)
              .fontColor('#E8EDF4')
            Blank()
            Button('刷新')
              .fontSize(12)
              .height(30)
              .backgroundColor('#22303F')
              .fontColor('#4C8DFF')
              .onClick(() => this.loadServerInfo())
          }
          .width('100%')
          .margin({ bottom: 8 })

          this.Kv('公网 IP', this.info.publicIp)
          Divider().color('#2A333F').margin({ top: 2, bottom: 2 })
          this.Kv('IP 归属地', this.info.geo)
          Divider().color('#2A333F').margin({ top: 2, bottom: 2 })
          this.Kv('运营商', this.info.isp)
          Divider().color('#2A333F').margin({ top: 2, bottom: 2 })
          this.Kv('探测延迟', this.info.latencyMs > 0 ? `${this.info.latencyMs} ms` : '未探测')
        }
        .width('100%')
        .padding(16)
        .margin({ top: 12, bottom: 16 })
        .backgroundColor('#1A2028')
        .borderRadius(14)
        .border({ width: 1, color: '#2A333F' })
      }
      .padding({ left: 14, right: 14, top: 12 })
    }
    .scrollBar(BarState.Off)
    .width('100%')
    .height('100%')
  }

  @Builder
  Tile(label: string, value: string, hint: string, valueColor: string) {
    Column() {
      Text(value)
        .fontSize(18)
        .fontWeight(FontWeight.Bold)
        .fontColor(valueColor)
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
      Text(label)
        .fontSize(11)
        .fontColor('#9AA7B8')
        .margin({ top: 4 })
      if (hint.length > 0) {
        Text(hint)
          .fontSize(10)
          .fontColor('#6B7785')
          .margin({ top: 2 })
      }
    }
    .alignItems(HorizontalAlign.Start)
    .layoutWeight(1)
    .padding({ top: 10, bottom: 10 })
  }

  @Builder
  Kv(k: string, v: string) {
    Row() {
      Text(k)
        .fontSize(13)
        .fontColor('#9AA7B8')
      Blank()
      Text(v && v.length > 0 ? v : '-')
        .fontSize(13)
        .fontColor('#E8EDF4')
        .layoutWeight(1)
        .textAlign(TextAlign.End)
        .maxLines(2)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
    }
    .width('100%')
    .padding({ top: 7, bottom: 7 })
  }

  // ============ 连接 ============
  @Builder
  ConnPage() {
    Column() {
      Row() {
        Text('当前转发连接')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .fontColor('#E8EDF4')
        Blank()
        Text(`${this.conns.length} 条`)
          .fontSize(12)
          .fontColor('#6B7785')
      }
      .width('100%')
      .padding({ left: 18, right: 18, top: 16, bottom: 10 })

      if (this.conns.length === 0) {
        Column() {
          Text(this.connected ? '暂无活跃连接' : '未连接到电脑端')
            .fontSize(13)
            .fontColor('#6B7785')
        }
        .width('100%')
        .layoutWeight(1)
        .justifyContent(FlexAlign.Center)
      } else {
        List({ space: 10 }) {
          ForEach(this.conns, (c: ConnItem) => {
            ListItem() {
              Column() {
                Row() {
                  Text(c.name)
                    .fontSize(15)
                    .fontWeight(FontWeight.Bold)
                    .fontColor('#4C8DFF')
                  Blank()
                  Text(fmtDuration(c.duration))
                    .fontSize(12)
                    .fontColor('#6B7785')
                }
                .width('100%')
                .margin({ bottom: 8 })

                Row() {
                  Text('来源')
                    .fontSize(12)
                    .fontColor('#9AA7B8')
                    .width(40)
                  Text(c.peer)
                    .fontSize(12)
                    .fontColor('#E8EDF4')
                    .layoutWeight(1)
                    .maxLines(1)
                    .textOverflow({ overflow: TextOverflow.Ellipsis })
                }
                .width('100%')
                .margin({ bottom: 4 })

                Row() {
                  Text('目标')
                    .fontSize(12)
                    .fontColor('#9AA7B8')
                    .width(40)
                  Text(c.target)
                    .fontSize(12)
                    .fontColor('#E8EDF4')
                    .layoutWeight(1)
                    .maxLines(1)
                    .textOverflow({ overflow: TextOverflow.Ellipsis })
                }
                .width('100%')
                .margin({ bottom: 8 })

                Row() {
                  Text(`↑ ${fmtBytes(c.bytesUp)}`)
                    .fontSize(12)
                    .fontColor('#4C8DFF')
                  Text(`↓ ${fmtBytes(c.bytesDown)}`)
                    .fontSize(12)
                    .fontColor('#3FBF7F')
                    .margin({ left: 14 })
                }
                .width('100%')
              }
              .width('100%')
              .padding(14)
              .backgroundColor('#1A2028')
              .borderRadius(12)
              .border({ width: 1, color: '#2A333F' })
            }
          }, (c: ConnItem) => `${c.name}-${c.peer}-${c.since}`)
        }
        .width('100%')
        .layoutWeight(1)
        .padding({ left: 14, right: 14, bottom: 16 })
        .scrollBar(BarState.Off)
      }
    }
    .width('100%')
    .height('100%')
  }

  // ============ 日志 ============
  @Builder
  LogPage() {
    Column() {
      // 筛选行
      Column() {
        Row() {
          ForEach(LOG_LEVELS, (lv: string) => {
            Text(lv === 'ALL' ? '全部' : lv)
              .fontSize(12)
              .fontColor(this.logLevel === lv ? '#101418' : '#9AA7B8')
              .backgroundColor(this.logLevel === lv ? '#4C8DFF' : '#222A34')
              .padding({ left: 10, right: 10, top: 5, bottom: 5 })
              .borderRadius(13)
              .margin({ right: 6 })
              .onClick(() => {
                this.logLevel = lv;
                this.loadLogs();
              })
          }, (lv: string) => lv)
        }
        .width('100%')

        Row() {
          TextInput({ placeholder: '搜索日志内容…', text: this.logKeyword })
            .fontSize(13)
            .height(38)
            .backgroundColor('#222A34')
            .fontColor('#E8EDF4')
            .placeholderColor('#6B7785')
            .layoutWeight(1)
            .onChange((v: string) => {
              this.logKeyword = v;
            })
            .onSubmit(() => this.loadLogs())
          Button('搜索')
            .fontSize(13)
            .height(38)
            .margin({ left: 8 })
            .backgroundColor('#22303F')
            .fontColor('#4C8DFF')
            .onClick(() => this.loadLogs())
        }
        .width('100%')
        .margin({ top: 10 })
      }
      .width('100%')
      .padding({ left: 14, right: 14, top: 12, bottom: 10 })

      Row() {
        Text(`共 ${this.logs.length} 条 · 保留最近 7 天`)
          .fontSize(11)
          .fontColor('#6B7785')
        Blank()
        Button('刷新')
          .fontSize(12)
          .height(28)
          .backgroundColor('#1E2732')
          .fontColor('#4C8DFF')
          .onClick(() => this.loadLogs())
      }
      .width('100%')
      .padding({ left: 18, right: 18, bottom: 8 })

      if (this.logs.length === 0) {
        Column() {
          Text(this.connected ? '暂无日志' : '未连接到电脑端')
            .fontSize(13)
            .fontColor('#6B7785')
        }
        .width('100%')
        .layoutWeight(1)
        .justifyContent(FlexAlign.Center)
      } else {
        List() {
          ForEach(this.logs, (l: LogLine, idx: number) => {
            ListItem() {
              Column() {
                Row() {
                  Text(l.time)
                    .fontSize(11)
                    .fontColor('#6B7785')
                  Text(l.level)
                    .fontSize(10)
                    .fontColor(levelColor(l.level))
                    .backgroundColor('#222A34')
                    .padding({ left: 5, right: 5, top: 1, bottom: 1 })
                    .borderRadius(4)
                    .margin({ left: 8 })
                  Text(l.module)
                    .fontSize(11)
                    .fontColor('#9AA7B8')
                    .margin({ left: 6 })
                  Blank()
                }
                .width('100%')

                Text(l.message)
                  .fontSize(12)
                  .fontColor(levelColor(l.level))
                  .width('100%')
                  .margin({ top: 4 })
                  .textAlign(TextAlign.Start)
              }
              .width('100%')
              .alignItems(HorizontalAlign.Start)
              .padding({ top: 9, bottom: 9, left: 4, right: 4 })
              .border({ width: { bottom: 1 }, color: '#1E2732' })
            }
          }, (l: LogLine, idx: number) => `${idx}-${l.time}-${l.message}`)
        }
        .width('100%')
        .layoutWeight(1)
        .padding({ left: 14, right: 14 })
        .scrollBar(BarState.Off)
      }
    }
    .width('100%')
    .height('100%')
  }

  // ============ 规则 ============
  @Builder
  RulePage() {
    Column() {
      Row() {
        Text('过滤规则')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .fontColor('#E8EDF4')
        Blank()
        Text(this.rules.mode === 'whitelist' ? '默认拒绝' : '默认放行')
          .fontSize(12)
          .fontColor(this.rules.mode === 'whitelist' ? '#E3B341' : '#4C8DFF')
          .backgroundColor('#222A34')
          .padding({ left: 8, right: 8, top: 4, bottom: 4 })
          .borderRadius(10)
      }
      .width('100%')
      .padding({ left: 18, right: 18, top: 16, bottom: 6 })

      Row() {
        Button(this.rules.mode === 'blacklist' ? '默认改为：拒绝' : '默认改为：放行')
          .fontSize(12)
          .height(32)
          .backgroundColor('#22303F')
          .fontColor('#4C8DFF')
          .onClick(async () => {
            const next = this.rules.mode === 'blacklist' ? 'whitelist' : 'blacklist';
            const r = await this.api.setRuleMode(next, this.rules.enabled);
            if (r.ok) {
              await this.loadRules();
            }
            promptAction.showToast({ message: r.ok ? '已切换' : (r.error ?? '失败') });
          })
        Button(this.rules.enabled ? '停用规则' : '启用规则')
          .fontSize(12)
          .height(32)
          .margin({ left: 10 })
          .backgroundColor('#22303F')
          .fontColor(this.rules.enabled ? '#E3B341' : '#3FBF7F')
          .onClick(async () => {
            const r = await this.api.setRuleMode(this.rules.mode, !this.rules.enabled);
            if (r.ok) {
              await this.loadRules();
            }
            promptAction.showToast({ message: r.ok ? '已更新' : (r.error ?? '失败') });
          })
        Blank()
        Button('刷新')
          .fontSize(12)
          .height(32)
          .backgroundColor('#1E2732')
          .fontColor('#4C8DFF')
          .onClick(() => this.loadRules())
      }
      .width('100%')
      .padding({ left: 14, right: 14, bottom: 10 })

      Text('默认策略只管"没写进列表的目标"：'
        + (this.rules.mode === 'blacklist' ? '放行' : '拒绝')
        + '；每条规则是拦还是放，点它右侧的徽章切换。')
        .fontSize(11)
        .fontColor('#6B7785')
        .width('100%')
        .padding({ left: 18, right: 18, bottom: 8 })

      // ---- 新增一条规则 ----
      Column() {
        Row() {
          Text('新增')
            .fontSize(12)
            .fontColor('#8B98A8')
            .width(38)
          TextInput({ text: this.newRuleHost, placeholder: '目标主机（* 表示任意）' })
            .fontSize(12)
            .height(34)
            .layoutWeight(1)
            .backgroundColor('#141A21')
            .fontColor('#E8EDF4')
            .onChange((v: string) => { this.newRuleHost = v; })
          TextInput({ text: this.newRulePorts, placeholder: '端口，如 3389' })
            .fontSize(12)
            .height(34)
            .width(120)
            .margin({ left: 8 })
            .backgroundColor('#141A21')
            .fontColor('#E8EDF4')
            .onChange((v: string) => { this.newRulePorts = v; })
        }
        .width('100%')

        Row() {
          TextInput({ text: this.newRuleNote, placeholder: '备注（可选）' })
            .fontSize(12)
            .height(34)
            .layoutWeight(1)
            .backgroundColor('#141A21')
            .fontColor('#E8EDF4')
            .onChange((v: string) => { this.newRuleNote = v; })
          // 类型选择：黑名单 / 白名单
          Text(this.newRuleAction === 'allow' ? '白名单' : '黑名单')
            .fontSize(12)
            .fontColor(this.newRuleAction === 'allow' ? '#3FBF7F' : '#FF7B72')
            .textAlign(TextAlign.Center)
            .height(34)
            .width(72)
            .margin({ left: 8 })
            .backgroundColor('#222A34')
            .borderRadius(8)
            .onClick(() => {
              this.newRuleAction = this.newRuleAction === 'allow' ? 'deny' : 'allow';
            })
          Button('添加')
            .fontSize(12)
            .height(34)
            .margin({ left: 8 })
            .backgroundColor('#22303F')
            .fontColor('#4C8DFF')
            .onClick(async () => {
              const port = this.newRulePorts.trim();
              if (port.length === 0) {
                promptAction.showToast({ message: '请填写端口（如 3389）' });
                return;
              }
              const host = this.newRuleHost.trim().length > 0 ? this.newRuleHost.trim() : '*';
              const res = await this.api.addRule(host, port, this.newRuleAction, this.newRuleNote.trim());
              if (res.ok) {
                this.newRulePorts = '';
                this.newRuleNote = '';
                await this.loadRules();
              }
              promptAction.showToast({ message: res.ok ? '规则已添加' : (res.error ?? '失败') });
            })
        }
        .width('100%')
        .margin({ top: 8 })
      }
      .width('100%')
      .padding({ left: 14, right: 14, bottom: 10 })

      if (this.rules.rules.length === 0) {
        Column() {
          Text('暂无规则')
            .fontSize(13)
            .fontColor('#6B7785')
        }
        .width('100%')
        .layoutWeight(1)
        .justifyContent(FlexAlign.Center)
      } else {
        List({ space: 8 }) {
          ForEach(this.rules.rules, (r: RuleItem) => {
            ListItem() {
              Row() {
                Column() {
                  Text(`${r.host}:${r.ports}`)
                    .fontSize(14)
                    .fontColor('#E8EDF4')
                    .maxLines(1)
                    .textOverflow({ overflow: TextOverflow.Ellipsis })
                  if (r.note && r.note.length > 0) {
                    Text(r.note)
                      .fontSize(11)
                      .fontColor('#6B7785')
                      .margin({ top: 3 })
                  }
                }
                .alignItems(HorizontalAlign.Start)
                .layoutWeight(1)

                // 类型徽章：点一下在黑名单/白名单之间切换，改完立即生效
                Text(r.action === 'allow' ? '白名单' : '黑名单')
                  .fontSize(11)
                  .fontColor(r.action === 'allow' ? '#3FBF7F' : '#FF7B72')
                  .backgroundColor('#222A34')
                  .padding({ left: 8, right: 8, top: 5, bottom: 5 })
                  .borderRadius(9)
                  .border({
                    width: 1,
                    color: r.action === 'allow' ? '#2C5A44' : '#5A2C2C'
                  })
                  .onClick(async () => {
                    const next = r.action === 'allow' ? 'deny' : 'allow';
                    const res = await this.api.setRuleAction(r.index, next);
                    if (res.ok) {
                      await this.loadRules();
                    }
                    promptAction.showToast({
                      message: res.ok ? (next === 'allow' ? '已改为白名单（放行）' : '已改为黑名单（拒绝）')
                        : (res.error ?? '失败')
                    });
                  })

                Button('删除')
                  .fontSize(12)
                  .height(30)
                  .margin({ left: 10 })
                  .backgroundColor('#3A2A2A')
                  .fontColor('#FF7B72')
                  .onClick(async () => {
                    const res = await this.api.removeRule(r.index);
                    if (res.ok) {
                      await this.loadRules();
                    }
                    promptAction.showToast({ message: res.ok ? '已删除' : (res.error ?? '失败') });
                  })
              }
              .width('100%')
              .padding(14)
              .backgroundColor('#1A2028')
              .borderRadius(12)
              .border({ width: 1, color: '#2A333F' })
            }
          }, (r: RuleItem) => `${r.index}-${r.host}-${r.ports}-${r.action}`)
        }
        .width('100%')
        .layoutWeight(1)
        .padding({ left: 14, right: 14, bottom: 16 })
        .scrollBar(BarState.Off)
      }
    }
    .width('100%')
    .height('100%')
  }

  // ============ 设置 ============
  @Builder
  SettingPage() {
    Scroll() {
      Column() {
        Column() {
          Text('电脑端连接')
            .fontSize(16)
            .fontWeight(FontWeight.Bold)
            .fontColor('#E8EDF4')
            .margin({ bottom: 4 })
          Text('填写运行「内网穿透助手」那台电脑的局域网 IP 和手机控制端口')
            .fontSize(11)
            .fontColor('#6B7785')
            .margin({ bottom: 14 })

          this.Field('电脑 IP / 主机名', this.host, '例如 192.168.1.100', (v: string) => {
            this.host = v;
          })
          this.Field('控制端口', this.port, '例如 8899', (v: string) => {
            this.port = v;
          })
          this.Field('访问令牌', this.token, '电脑端日志里会显示', (v: string) => {
            this.token = v;
          })

          Button('保存并测试连接')
            .width('100%')
            .height(44)
            .fontSize(15)
            .margin({ top: 18 })
            .backgroundColor('#4C8DFF')
            .fontColor('#FFFFFF')
            .onClick(() => this.saveSettings())
        }
        .width('100%')
        .padding(16)
        .backgroundColor('#1A2028')
        .borderRadius(14)
        .border({ width: 1, color: '#2A333F' })

        Column() {
          Text('怎么开启手机控制？')
            .fontSize(15)
            .fontWeight(FontWeight.Bold)
            .fontColor('#E8EDF4')
            .margin({ bottom: 10 })
          Text('1. 在电脑上打开「内网穿透助手」\n' +
            '2. 启动服务端或客户端（任一）\n' +
            '3. 程序会自动开启手机控制端口，\n' +
            '    并在日志里打印出访问令牌\n' +
            '4. 把电脑 IP、端口、令牌填到上面，\n' +
            '    点「保存并测试连接」\n' +
            '5. 手机与电脑需在同一局域网内')
            .fontSize(12)
            .lineHeight(20)
            .fontColor('#9AA7B8')
        }
        .width('100%')
        .padding(16)
        .margin({ top: 14 })
        .backgroundColor('#1A2028')
        .borderRadius(14)
        .border({ width: 1, color: '#2A333F' })

        Column() {
          Text('重要说明')
            .fontSize(15)
            .fontWeight(FontWeight.Bold)
            .fontColor('#E3B341')
            .margin({ bottom: 8 })
          Text('鸿蒙系统目前不支持运行 Python。本 App 是「远程控制台」，' +
            '真正的穿透引擎仍在电脑上运行 —— 手机负责查看状态、日志，' +
            '以及远程启停服务。这样既能在手机上管理，也不改变电脑端任何逻辑。')
            .fontSize(12)
            .lineHeight(20)
            .fontColor('#9AA7B8')
        }
        .width('100%')
        .padding(16)
        .margin({ top: 14, bottom: 16 })
        .backgroundColor('#1A2028')
        .borderRadius(14)
        .border({ width: 1, color: '#3A3320' })
      }
      .padding({ left: 14, right: 14, top: 12 })
    }
    .scrollBar(BarState.Off)
    .width('100%')
    .height('100%')
  }

  @Builder
  Field(label: string, value: string, placeholder: string, onChanged: (v: string) => void) {
    Column() {
      Text(label)
        .fontSize(12)
        .fontColor('#9AA7B8')
        .margin({ bottom: 6 })
        .alignSelf(ItemAlign.Start)
      TextInput({ placeholder: placeholder, text: value })
        .fontSize(14)
        .height(42)
        .backgroundColor('#222A34')
        .fontColor('#E8EDF4')
        .placeholderColor('#6B7785')
        .onChange(onChanged)
    }
    .width('100%')
    .margin({ bottom: 14 })
  }
}
