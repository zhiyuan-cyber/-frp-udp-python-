# 内网穿透助手 · 鸿蒙手机端（ArkTS）

在鸿蒙手机上查看和管理电脑上的「内网穿透助手」。

---

## 一、先说清楚：为什么不是"把 Python 编译成鸿蒙应用"

这是必须理解的前提，否则会一直走错方向。

| 事实 | 说明 |
| --- | --- |
| **鸿蒙不支持 Python 应用开发** | HarmonyOS NEXT 官方应用语言只有 **ArkTS** 和 **C/C++（NAPI）**。Java 已随 NEXT 淘汰。Python 在鸿蒙上只用于**构建脚本、自动化测试**，不是应用开发语言。 |
| **没有 Python → .hap 的编译工具** | 不存在能把 Python 源码编译成鸿蒙安装包的工具链。所谓"编译成鸿蒙应用"在技术上不成立。 |
| **本项目的 GUI 是 tkinter + Win32** | `gui.py` 用了 tkinter 画界面，`tray.py` 用 `ctypes` 直调 Win32 做托盘、窗口定位、DPI 感知。这些在鸿蒙上**没有对应 API**，必须整体重写。 |
| **异步网络栈也不通用** | `frps.py` / `frpc.py` 基于 Python 的 `asyncio` + `ssl`，依赖 CPython 运行时。 |

社区确实有"ArkTS 界面 + C++ NAPI 桥接 + Python 运行时打 HNP 包"的玩法，
但那要求先重写全部界面，再把 CPython 塞进包里 —— 工程量巨大，
而且**托盘、系统代理、后台常驻**这些能力在鸿蒙上受严格限制，做不成一样的体验。

### 本方案的做法

**分工**：穿透引擎继续跑在电脑上（一行不改），手机 App 做**远程控制台**。

```
┌─────────────────┐         HTTP / JSON          ┌──────────────────┐
│  鸿蒙手机 App    │  ──────────────────────────▶ │  电脑上的        │
│  （本工程）      │   X-Frp-Token 鉴权            │  内网穿透助手     │
│                 │  ◀────────────────────────── │  （Python 引擎）  │
└─────────────────┘   状态/流量/连接/日志/规则      └──────────────────┘
                                                          │
                                                    真正的穿透隧道
```

这样你在手机上能：**看实时状态与流量**、**翻最近 7 天日志**、
**远程启停服务端/客户端**、**增删过滤规则** —— 而电脑端的穿透逻辑完全不改。

---

## 二、它长什么样

五个标签页，深色 Clash Verge 风格，与电脑端配色一致：

| 页面 | 内容 |
| --- | --- |
| **首页** | 运行状态、启动/停止服务端与客户端、上行/下行速度、累计流量、活跃连接与峰值、在线客户端、运行时长、拒绝/鉴权失败计数、服务器信息（公网 IP / 归属地 / 运营商 / 延迟） |
| **连接** | 当前每条转发连接的代理名、来源、目标、上下行字节、持续时长 |
| **日志** | 最近 7 天日志；级别筛选（全部/DEBUG/INFO/WARNING/ERROR）+ 关键字搜索；按级别着色 |
| **规则** | 规则列表（每条带**黑名单/白名单**徽章，点一下即切换）、新增（可选类型）/删除、默认策略切换、总开关 |
| **设置** | 电脑 IP、控制端口、访问令牌；保存并测试连接 |

数据每 2 秒自动刷新（日志页按需刷新，省流量）。

---

## 三、构建步骤

### 1. 环境要求

| 项目 | 版本 |
| --- | --- |
| DevEco Studio | **5.0 Release 及以上**（建议 6.0.2+，对应 HarmonyOS 6） |
| HarmonyOS SDK | **API 12 及以上** |
| 手机系统 | HarmonyOS NEXT（5.0+） |
| JDK | DevEco Studio 自带，无需单独装 |

> ⚠️ **构建必须在装了 DevEco Studio 的 Windows / macOS 上做。**
> 本仓库当前所在机器没有装 DevEco Studio、鸿蒙 SDK、hvigor、ohpm，
> 因此**无法在这里产出 `.hap` 安装包** —— 请在你自己的机器上完成这一步。

### 2. 打开工程

1. 打开 DevEco Studio → **File → Open**
2. 选中本目录（`harmonyos/`，即含有 `build-profile.json5` 的那一层）
3. 首次打开会提示同步，等待右下角 **Sync** 完成
   （会通过 ohpm 拉取 `@ohos/hvigor-ohos-plugin`，需要联网；
   若公司网络有代理，请先在 Settings → HTTP Proxy 配好）

### 3. 配置签名（真机调试必需）

1. **File → Project Structure → Signing Configs**
2. 勾选 **Automatically generate signature**
3. 用华为开发者账号登录（免费注册即可）
4. 等它自动生成证书与 Profile —— 这一步需要手机已连接或稍后再连

> `build-profile.json5` 里 `signingConfigs` 的字段留空了，
> 就是留给 DevEco Studio 自动填的。**不要手工乱填**。

### 4. 运行到手机

1. 手机开启 **开发者模式** + **USB 调试**
   （设置 → 关于本机 → 连点版本号 7 次；再进 开发者选项 → USB 调试）
2. USB 连接电脑，手机弹窗选「允许调试」
3. DevEco Studio 右上角设备列表选中你的手机
4. 点绿色 ▶ **Run** —— 首次约 1-3 分钟

也可以**Build → Build Hap(s)/APP(s) → Build Hap(s)** 产出
`entry/build/default/outputs/default/entry-default-signed.hap`，
再传到手机点击安装（需允许安装未知来源应用）。

---

## 四、连接电脑（关键步骤）

鸿蒙默认**禁止明文 HTTP 流量**。本 App 访问的是局域网内的 `http://` 地址，
所以除了在 `module.json5` 里声明 `ohos.permission.INTERNET` 之外，
还需要在工程里配置网络安全策略以放行明文。

**如果运行时请求失败、日志报 `Cleartext HTTP traffic not permitted` /
`2300xxx` 之类的错误**，请按下面任一方式处理：

### 方式 A（推荐，简单）：配置 network_config

1. 在 `entry/src/main/resources/base/profile/` 下新建 `network_config.json`：

```json
{
  "network-security-config": {
    "base-config": {
      "cleartextTrafficPermitted": true
    }
  }
}
```

2. 在 `module.json5` 的 `module` 节点内加上：

```json5
"metadata": [
  {
    "name": "ohos.net.network_security_config",
    "resource": "$profile:network_config"
  }
]
```

> 为避免误伤，也可以只放行你的电脑网段，把 `base-config` 换成
> `domain-config` 列出 `192.168.1.100` 这类具体 IP。

### 方式 B：给电脑端套一层 HTTPS

在电脑上用 Nginx / Caddy 给 `8899` 端口做 TLS 反代，
手机端把地址改成 `https://`（`ApiClient.ets` 里把 `http://` 改成 `https://`）。
自签证书需要在手机上信任，比较麻烦，一般用方式 A 就够。

### 在电脑端拿到地址和令牌

启动「内网穿透助手」后，打开 **「关于」页 → 手机控制（鸿蒙 App）**，
能看到：

```
接口地址   http://192.168.1.100:8899   （令牌：164023-a1b2c3d4）
```

把 **IP**、**端口 8899**、**令牌** 填进手机 App 的「设置」页，点
**保存并测试连接**。看到「连接成功」就可以用了。

> 手机和电脑必须在**同一个局域网**（同一个 WiFi）。
> 程序启动的日志里也会打印这组信息，可在「运行日志」页直接看。

### 电脑端相关参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--mobile-api-port 8899` | 8899 | 手机控制端口，被占用会自动往后顺延 |
| `--mobile-api-localhost` | 关 | 只允许本机访问（更安全，手机就连不上了） |
| `--no-mobile-api` | 关 | 完全关闭这个接口 |

---

## 五、安全提醒

- 令牌每次启动**随机生成**，用 `hmac.compare_digest` 比对（防时序攻击）。
- 接口**只监听局域网**，但默认是 `0.0.0.0` —— 意味着同网段任何设备都能扫到端口。
  **不要把 8899 端口映射到公网。**
- 只需要本机用时，加 `--mobile-api-localhost`。
- 接口能力仅限：读状态/日志/规则 + 启停 + 改规则。
  **不提供文件读写，不执行任意命令。**

---

## 六、目录结构

```
harmonyos/
├── AppScope/
│   ├── app.json5                    应用级配置（bundleName / 版本 / 图标）
│   └── resources/base/element/      应用名
├── entry/                           主模块
│   ├── src/main/
│   │   ├── module.json5             模块配置 + 权限（INTERNET / GET_NETWORK_INFO）
│   │   ├── ets/
│   │   │   ├── entryability/
│   │   │   │   └── EntryAbility.ets 应用入口（沉浸式全屏）
│   │   │   ├── pages/
│   │   │   │   └── Index.ets        主界面（五个标签页）
│   │   │   ├── model/
│   │   │   │   ├── Models.ets       与电脑端 API 对应的数据模型
│   │   │   │   └── ApiClient.ets    HTTP 客户端（带令牌鉴权）
│   │   │   ├── common/
│   │   │   │   ├── Fmt.ets          字节/速度/时长格式化、级别配色
│   │   │   │   └── Prefs.ets        配置持久化（IP/端口/令牌）
│   │   │   └── components/
│   │   │       └── Widgets.ets      复用小组件
│   │   └── resources/               字符串 / 颜色 / 图标
│   └── hvigor/hvigor-config.json5
├── hvigor/hvigor-config.json5
├── build-profile.json5              构建配置（签名留空待自动生成）
├── hvigorfile.ts
└── oh-package.json5
```

---

## 七、常见问题

**Q：Sync 失败 / 拉不到 hvigor 插件？**
配好 HTTP Proxy（Settings → HTTP Proxy），或换成能访问 ohpm 仓库的网络。

**Q：装到手机后一直显示「未连接」？**
按顺序排查：
1. 电脑端「关于」页确认接口已开启、地址是什么；
2. 手机浏览器访问 `http://<电脑IP>:8899/api/ping` —— 返回
   `{"ok": false, "error": "访问令牌不正确"}` 就说明网络通了，只是没带令牌；
   如果超时，是网络不通（防火墙 / 不同网段 / 电脑端没开）；
3. 手机上 IP、端口、令牌三项都要跟电脑端显示的一致（注意不要有多余空格）；
4. Windows 防火墙可能拦了 8899 —— 首次启动 Python 时若弹窗询问，
   要选「允许访问」，且勾上「专用网络」。

**Q：能不能让手机 App 自己当穿透服务端？**
不能。那需要完整的 CPython 运行时 + socket 服务能力 + 后台常驻权限，
鸿蒙不提供这些给第三方应用，也无法把 `frps.py` 搬过去。

**Q：日志为什么只有最近 7 天？**
电脑端按天轮转、保留 7 份（`logs/app.log` 与 `app.log.YYYY-MM-DD`），
手机端读的就是这批文件。详见主 README 的「运行日志」一节。
