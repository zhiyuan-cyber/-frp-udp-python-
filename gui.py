"""
gui.py —— 图形界面版（Clash Verge 风格）

布局：
    ┌──────────┬──────────────────────────────────────────┐
    │ 侧边栏    │  内容区（按模块切换）                      │
    │ 首页      │  首页：状态 / 流量图表 / 指标 / 服务器信息   │
    │ 服务端    │  服务端：单机开监听                        │
    │ 客户端    │  客户端：把本机服务映射出去                 │
    │ 过滤规则  │  规则：限制哪些内网目标不允许被转发          │
    │ 运行日志  │  日志：实时滚动                            │
    │ 关于      │  关于：作者信息与文件位置                   │
    └──────────┴──────────────────────────────────────────┘

设计取舍：
    · **不引入任何第三方 UI 库**。本机 pip 连不上 PyPI，而且要让 exe 保持
      "单文件、零额外依赖"；圆角卡片、流量图表、开关全部用 tkinter 的 Canvas
      自绘（见 ui_kit.py），效果够用且绝不缺依赖。
    · **界面与后端彻底解耦**：后端只暴露一个 Stats 快照（protocol.Stats.snapshot），
      界面每秒读一次，读不到就当 0 —— 后端怎么改都不会把界面带崩。
    · **网络逻辑全部在后台线程的事件循环里**，日志经队列回传到界面线程渲染
      （tkinter 不是线程安全的，跨线程直接改控件会随机崩溃）。

打包：
    python build_exe.py      # 见同目录 build_exe.py
"""

import asyncio
import contextlib
import logging
import os
import queue
import re
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

import about          # 作者/程序信息集中在这里，改 about.py 全项目生效
import netinfo        # 服务器信息探测（解析 / 归属地 / 延迟）
import rules as rules_mod   # 转发过滤规则
import ui_kit as uk   # 界面组件（圆角卡片 / 图表 / 导航）

# ---------------------------------------------------------------- 路径
# 打包后 PyInstaller 会把只读资源解到临时目录（sys._MEIPASS）；
# 源码运行时就是脚本所在目录。两者必须分开：
#   BASE_DIR —— 放**数据**（证书、token、规则），必须在 exe 旁边，用户看得见
#   SRC_DIR  —— 放**只读资源**（图标），打包后在临时目录里
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
    SRC_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    SRC_DIR = BASE_DIR

sys.path.insert(0, SRC_DIR)

import protocol  # noqa: E402  （导入以触发 logger 初始化）
from protocol import (  # noqa: E402
    cert_days_left,
    format_bytes,
    format_duration,
    format_speed,
    get_logger,
    parse_log_level,
)

LOG = get_logger("gui", parse_log_level("INFO"))

DATA_DIR = BASE_DIR
CERT_DIR = os.path.join(DATA_DIR, "certs")
TOKEN_FILE = os.path.join(DATA_DIR, "tokens.txt")
RULES_FILE = os.path.join(DATA_DIR, "rules.json")
GEO_CACHE_FILE = os.path.join(DATA_DIR, "geo-cache.json")

# ---------------------------------------------------------------- 手机控制接口
# 鸿蒙手机 App（harmonyos/ 目录）通过这个 HTTP 接口查看状态、日志并远程控制。
# 鸿蒙不支持 Python，所以穿透引擎仍跑在电脑上，手机只做"控制台"。
# 默认监听 0.0.0.0 才能被手机访问；端口被占用会自动往后顺延。
# 禁用：命令行加 --no-mobile-api
MOBILE_API_HOST = "0.0.0.0"
MOBILE_API_PORT = 8899

# ---------------------------------------------------------------- 规则类型
# 每条规则自带类型（黑名单=命中即拒绝 / 白名单=命中即放行），
# 列表里可以黑白混排；下拉改完立即写盘生效。
# 配色：黑名单红、白名单绿 —— 扫一眼就能分清哪条在拦、哪条在放。
ACTION_OPTIONS = [
    (rules_mod.ACTION_DENY, rules_mod.ACTION_LABEL[rules_mod.ACTION_DENY]),
    (rules_mod.ACTION_ALLOW, rules_mod.ACTION_LABEL[rules_mod.ACTION_ALLOW]),
]
ACTION_COLORS = {
    rules_mod.ACTION_DENY: (uk.ERR, uk.ERR_SOFT),
    rules_mod.ACTION_ALLOW: (uk.OK, uk.OK_SOFT),
}
MODE_OPTIONS = [
    (rules_mod.MODE_BLOCK, rules_mod.MODE_LABEL[rules_mod.MODE_BLOCK]),
    (rules_mod.MODE_ALLOW, rules_mod.MODE_LABEL[rules_mod.MODE_ALLOW]),
]
MODE_COLORS = {
    rules_mod.MODE_BLOCK: (uk.TEXT_SUB, uk.BG_SOFT),
    rules_mod.MODE_ALLOW: (uk.WARN, uk.WARN_SOFT),
}

ASSETS_DIR = os.path.join(SRC_DIR, "assets")
ICON_ICO = os.path.join(ASSETS_DIR, "icon.ico")
ICON_PNG = os.path.join(ASSETS_DIR, "icon.png")

APP_TITLE = about.APP_TITLE
AUTHOR_NAME = about.AUTHOR_NAME
AUTHOR_EMAIL = about.AUTHOR_EMAIL
AUTHOR_HOMEPAGE = about.AUTHOR_HOMEPAGE


# ======================================================================
# 一、日志回传：让 logging 的输出同时进文件和控制台窗口
# ======================================================================
class QueueLogHandler(logging.Handler):
    """把 logging 记录塞进队列，由界面线程取出显示。

    为什么不让 logging 直接写 Text？
        logging 可能来自后台线程（服务端/客户端各跑一条事件循环），
        而 tkinter 的控件只能在主线程碰 —— 跨线程直接改控件会随机崩溃。
        队列是标准的"线程间传话"做法。
    """

    def __init__(self, log_queue: "queue.Queue[tuple[str, str]]"):
        super().__init__()
        self.log_queue = log_queue
        self.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.log_queue.put_nowait((record.levelname, self.format(record)))
        except (queue.Full, Exception):     # noqa: BLE001 日志绝不能再抛异常
            pass


def install_gui_logging(log_queue: "queue.Queue[tuple[str, str]]") -> None:
    """把界面日志 handler 挂到**所有** logger 上。

    ★ 关键点（踩过的坑）：
      本项目的 frps / frpc / tray / frp.* 都是 propagate=False 的独立
      logger，只往 root 上挂 handler 的话，它们的日志一条都进不了界面
      —— 表现就是"日志页只有界面自己那几行、看着像不显示"。
      所以这里直接调 protocol.install_logging()，逐个别名挂上去。
    """
    handler = QueueLogHandler(log_queue)
    handler.setLevel(logging.DEBUG)
    protocol.install_logging([handler], level=logging.DEBUG)


# ======================================================================
# 二、证书与 token 准备
# ======================================================================
def _split_hosts(text: str) -> "list[str]":
    """把用户输入的一串地址拆成列表。

    逗号、中文逗号、分号、空格、换行随便用 —— 用户不该为分隔符记规则。
    """
    out = []
    normalized = (str(text or "")
                  .replace("，", ",").replace("；", ";").replace(";", ","))
    for chunk in normalized.split(","):
        for part in chunk.split():
            h = part.strip()
            if h and h not in out:
                out.append(h)
    return out


def _cert_hosts(extra=None) -> "list[str]":
    """证书里始终要覆盖的地址 = 用户填的地址 + 本机回环。

    为什么固定带上 localhost / 127.0.0.1？
      自检（--selftest）、同机调试、以及"服务端与客户端在同一台机器"
      这几种情况都靠 127.0.0.1 连接。漏了它们，自检会直接失败。
    """
    hosts = []
    for h in list(extra or []) + ["localhost", "127.0.0.1"]:
        h = (h or "").strip()
        if h and h not in hosts:
            hosts.append(h)
    return hosts


def generate_certs(out_dir: str, hosts: list, reuse_ca: bool = True,
                   log=print) -> None:
    """生成一套自签证书；reuse_ca=True 时沿用目录里已有的 CA。

    ★ 为什么重签要复用 CA？
      客户端手里只认 ca.crt。如果每改一次证书就新建一个 CA，
      所有客户端都得重新导入连接包 —— 换个 IP 就要全场换钥匙。
      复用 CA 则只换服务端证书，客户端无感，这才叫"能改"。
    """
    import gen_cert
    os.makedirs(out_dir, exist_ok=True)

    ca_key = ca_cert = None
    if reuse_ca:
        ca_key, ca_cert = gen_cert.load_ca(
            os.path.join(out_dir, "ca.crt"),
            os.path.join(out_dir, "ca.key"))
    if ca_key is None or ca_cert is None:
        ca_key, ca_cert = gen_cert.build_ca()
        log("已新建 CA：客户端需要重新导入连接包，才能校验新证书")

    srv_key, srv_cert = gen_cert.build_server_cert(ca_key, ca_cert, hosts)
    gen_cert.write_pem(os.path.join(out_dir, "ca.crt"), ca_cert)
    gen_cert.write_pem(os.path.join(out_dir, "ca.key"), None,
                       key=ca_key, key_only=True)
    gen_cert.write_pem(os.path.join(out_dir, "server.crt"), srv_cert)
    gen_cert.write_pem(os.path.join(out_dir, "server.key"), None,
                       key=srv_key, key_only=True)


def ensure_certs(hosts, out_dir: str, log=print, force: bool = False) -> bool:
    """确保证书存在且 SAN 覆盖所需地址；不满足就（复用 CA）重签。

    ★ 这是本次修复的核心之一。
      旧实现只检查"三个文件在不在"，在就跳过。于是：
        · 服务端证书里只有 localhost → 客户端拿公网 IP 连，主机名必然不匹配；
        · 用户改了公网 IP → 程序仍认为"证书已存在"，永远不重签；
        · 客户端模式还会顺手造一套没用的服务端证书，成为排查时的烟雾弹。
      现在改为比对 SAN：缺哪个地址就补签，CA 保持不变。
    """
    if isinstance(hosts, str):
        hosts = [hosts]
    hosts = _cert_hosts(hosts)

    crt = os.path.join(out_dir, "server.crt")
    key = os.path.join(out_dir, "server.key")
    ca = os.path.join(out_dir, "ca.crt")
    complete = all(os.path.exists(p) for p in (crt, key, ca))

    if complete and not force:
        import gen_cert
        if gen_cert.cert_covers(crt, hosts):
            return True
        log("服务端证书未覆盖 %s，自动重签服务端证书"
            "（CA 不变，客户端无需更换 ca.crt）", "、".join(hosts))

    try:
        generate_certs(out_dir, hosts, reuse_ca=True, log=log)
    except Exception as exc:            # noqa: BLE001
        log("生成证书失败：%s", exc)
        return False
    log("证书已就绪：%s（登记地址：%s）", out_dir, "、".join(hosts))
    return True


def ensure_client_ca(out_dir: str, log=print) -> bool:
    """客户端侧只检查 ca.crt 是否就位，绝不生成服务端证书。

    ★ 旧版客户端启动时会 ensure_certs(服务器地址)，在本机生成一套
      "看起来完全正确"的 server.crt / server.key。可客户端根本用不上它们
      （校验只认 ca.crt），却会让人误以为证书没问题 —— 排查时最误导人的
      就是这种东西。缺失时应当明确提示去"导入连接包"。
    """
    ca = os.path.join(out_dir, "ca.crt")
    if os.path.exists(ca):
        return True
    log("客户端缺少 ca.crt：请先用「导入连接包」导入服务端导出的包")
    return False


def ensure_token(path: str, log=print) -> str:
    """确保 token 文件存在且至少有一个可用 token。"""
    token = ""
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        token = line
                        break
        except OSError:
            token = ""
    if token:
        return token

    import secrets
    token = secrets.token_urlsafe(24)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# 每行一个 token，# 开头为注释；首行为主 token\n")
        f.write("# 轮换时把新 token 写在最上面，旧 token 留一行，等客户端换完再删\n")
        f.write(token + "\n")
    log("已生成新 token 并写入 %s", path)
    return token


# ======================================================================
# 三、运行器：把"跑事件循环"这件事和界面隔开
# ======================================================================
class Runner:
    """在后台线程里跑一条 asyncio 事件循环。

    holder 用来把跑起来的实例（Frps / Frpc）暴露给界面 ——
    界面靠它拿到 Stats 做流量统计。
    """

    def __init__(self):
        self.thread = None
        self.loop = None
        self.task = None
        self.holder: dict = {}

    @property
    def running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    @property
    def obj(self):
        """跑起来的服务端/客户端实例（没跑时为 None）。"""
        return self.holder.get("obj")

    def start(self, coro_factory, on_stopped=None) -> None:
        self.holder.clear()

        def _thread_main():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                self.task = self.loop.create_task(coro_factory())
                self.loop.run_until_complete(self.task)
            except asyncio.CancelledError:
                pass
            except Exception as exc:    # noqa: BLE001
                LOG.exception("后台任务异常退出：%s", exc)
            finally:
                with contextlib.suppress(Exception):
                    pending = asyncio.all_tasks(self.loop)
                    for t in pending:
                        t.cancel()
                    if pending:
                        self.loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True))
                with contextlib.suppress(Exception):
                    self.loop.close()
                self.loop = None
                self.thread = None
                if on_stopped is not None:
                    try:
                        on_stopped()
                    except Exception:   # noqa: BLE001
                        pass

        self.thread = threading.Thread(target=_thread_main, daemon=True)
        self.thread.start()

    def stop(self, on_stopped=None) -> None:
        """请求停止。任务跑在别的线程，只能靠 call_soon_threadsafe 去取消。"""
        def _cancel():
            if self.task is not None and not self.task.done():
                self.task.cancel()
            elif on_stopped is not None:
                on_stopped()

        if self.loop is not None:
            try:
                self.loop.call_soon_threadsafe(_cancel)
            except RuntimeError:
                if on_stopped is not None:
                    on_stopped()
        elif on_stopped is not None:
            on_stopped()


# ======================================================================
# 四、窗口图标
# ======================================================================
def set_windows_app_id(app_id: str = "jsdczd.frtunnel.assistant.1") -> None:
    """给本进程一个独立的 AppUserModelID。

    Windows 按这个 ID 给任务栏按钮分组、并取分组代表的图标。
    不设置时用 python 直接跑会被归到 python.exe 那组，任务栏显示 Python 图标。
    """
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception:                   # noqa: BLE001
        pass


def apply_window_icon(window: tk.Misc) -> None:
    """把 assets/icon.* 应用到窗口（标题栏 + 任务栏）。

    ★ 带 default 的写法只对"之后新建的窗口"生效，**对当前窗口无效**，
      所以必须不带 default 地再设一遍（实测只写 default 时 WM_GETICON 返回 0）。
    """
    if os.path.exists(ICON_ICO):
        for kw in ({}, {"default": ICON_ICO}):
            try:
                window.iconbitmap(**kw)
            except tk.TclError as exc:
                LOG.debug("设置 iconbitmap(%s) 失败：%s", kw, exc)

    if os.path.exists(ICON_PNG):
        try:
            img = tk.PhotoImage(file=ICON_PNG)
            window._icon_photo_ref = img   # 必须留引用，否则被 GC 后图标复原
            window.iconphoto(True, img)
        except tk.TclError as exc:
            LOG.debug("设置 iconphoto 失败：%s", exc)


# ======================================================================
# 五、通用小工具
# ======================================================================
def open_url(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception as exc:            # noqa: BLE001
        LOG.warning("无法打开链接 %s：%s", url, exc)


def make_link_label(parent, text: str, target: str, **kw) -> tk.Label:
    """看起来像链接、点了会用浏览器打开的标签。"""
    bg = kw.pop("bg", uk.BG_CARD)
    lbl = tk.Label(parent, text=text, fg=uk.ACCENT, bg=bg, cursor="hand2",
                   font=(uk.FONT_UI, 9, "underline"), **kw)
    lbl.bind("<Button-1>", lambda _e: open_url(target))
    return lbl


def _field(parent, label: str, variable, hint: str = "", width: int = 22,
           bg: str = uk.BG_CARD):
    """表单一行：标签 + 输入框 + 灰色说明。"""
    row = tk.Frame(parent, bg=bg)
    row.pack(fill="x", pady=4)

    tk.Label(row, text=label, font=uk.ui_font(10), bg=bg, fg=uk.TEXT_SUB,
             width=12, anchor="e").pack(side="left")

    ent = tk.Entry(row, textvariable=variable, width=width,
                   font=uk.ui_font(11), relief="flat", bg=uk.BG_SOFT,
                   fg=uk.TEXT, insertbackground=uk.TEXT,
                   highlightthickness=1, highlightbackground=uk.BORDER,
                   highlightcolor=uk.ACCENT)
    ent.pack(side="left", padx=(8, 10), ipady=4)

    if hint:
        tk.Label(row, text=hint, font=uk.ui_font(9), bg=bg,
                 fg=uk.TEXT_MUTED, anchor="w").pack(side="left")
    return ent


def _hint(parent, text: str, bg: str = uk.BG_CARD):
    lbl = tk.Label(parent, text=text, font=uk.ui_font(9), bg=bg,
                   fg=uk.TEXT_MUTED, justify="left", anchor="w")
    lbl.pack(fill="x", pady=(6, 0))
    return lbl


def _section(parent, text: str, bg: str = uk.BG_CARD, pady=(14, 4)):
    tk.Label(parent, text=text, font=uk.ui_font(11, "bold"), bg=bg,
             fg=uk.TEXT).pack(anchor="w", pady=pady)


def _bullet(parent, text: str, bg: str = uk.BG_CARD, color: str = uk.TEXT_SUB):
    row = tk.Frame(parent, bg=bg)
    row.pack(fill="x", pady=1)
    tk.Label(row, text="•", font=uk.ui_font(10), bg=bg,
             fg=uk.TEXT_MUTED).pack(side="left", padx=(4, 6))
    tk.Label(row, text=text, font=uk.ui_font(10), bg=bg, fg=color,
             anchor="w", justify="left").pack(side="left")
    return row


# ======================================================================
# 六、主窗口
# ======================================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        # ★ DPI 缩放要在建控件之前校准：
        #   它同时决定 tk scaling（字号）与 uk.dp()（像素尺寸）。
        scale = uk.init_scaling(self)
        self.title(APP_TITLE)
        # 窗口尺寸按屏幕自适应：高 DPI 下 dp() 会把窗口放大，
        # 写死数值很容易超出屏幕（实测 125% 时算出来比屏幕还高，底部被切）。
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        width = min(uk.dp(1060), max(uk.dp(820), sw - uk.dp(80)))
        height = min(uk.dp(700), max(uk.dp(560), sh - uk.dp(110)))
        self.geometry("%dx%d" % (width, height))
        self.minsize(min(uk.dp(900), width), min(uk.dp(560), height))
        self.configure(bg=uk.BG_PAGE)
        LOG.info("界面缩放 %.2fx（DPI %d），窗口 %dx%d，屏幕 %dx%d",
                 scale, round(self.winfo_fpixels("1i")), width, height, sw, sh)

        self.log_queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
        install_gui_logging(self.log_queue)

        self.server_runner = Runner()
        self.client_runner = Runner()

        # 过滤规则（服务端与客户端共用一份；客户端只读它做判定）
        self.rules = rules_mod.RuleSet.load(RULES_FILE)

        # 服务器信息探测（后台线程）
        self.probe = netinfo.ServerProbe(GEO_CACHE_FILE)

        # 流量统计状态
        self._last_snap = None
        self._last_ts = None
        self._rate_up = 0.0
        self._rate_down = 0.0
        # 连接列表的行复用池 + 目标进程名的短缓存
        self._conn_rows = {}
        self._owner_cache = {}

        self._nav_items = {}
        self._pages = {}
        self._current_page = None
        self._scroll_areas = {}          # {页面名: (canvas, inner)}，供滚轮路由
        self.tray = None                 # 托盘图标（首次最小化时才创建）
        self._really_quit = False        # 托盘菜单点"退出"时置位
        self.mobile_api = None           # 手机控制接口（供鸿蒙 App 访问）
        self._mb_bridge = None
        self._mobile_busy = False
        self._last_probe = None           # 最近一次服务器信息探测结果
        # 手机接口在 HTTP 线程里读它 —— 只能是纯数据，不能是控件。
        # 由 _update_stats()（主线程）每次刷新时写进来。
        self._clients_cached = 0
        self._mobile_snap_cache = {}

        apply_window_icon(self)

        self._build_style()
        self._build_layout()
        self._build_pages()

        self.show_page("home")
        self._poll_logs()
        self._tick_stats()
        self._setup_tray()
        self._setup_minimize_behaviour()
        if os.environ.get("FRP_NO_MOBILE_API") != "1":
            self._start_mobile_api()

        LOG.info("%s 已就绪。数据目录：%s", APP_TITLE, DATA_DIR)
        LOG.info("作者：%s  |  %s  |  %s", AUTHOR_NAME, AUTHOR_EMAIL, AUTHOR_HOMEPAGE)
        if self.rules.rules:
            LOG.info("已载入过滤规则：%s", self.rules.stats_line())

    # ---------------- 样式 ----------------
    def _build_style(self):
        style = ttk.Style(self)
        with contextlib.suppress(tk.TclError):
            style.theme_use("vista")
        style.configure("Vertical.TScrollbar", background=uk.BG_SOFT,
                        troughcolor=uk.BG_PAGE, bordercolor=uk.BG_PAGE,
                        arrowcolor=uk.TEXT_MUTED, relief="flat")

    # ---------------- 骨架 ----------------
    def _build_layout(self):
        side = tk.Frame(self, bg=uk.BG_SIDEBAR, width=uk.dp(uk.SIDEBAR_W))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(self, bg=uk.BORDER, width=1).pack(side="left", fill="y")

        # 品牌区
        brand = tk.Frame(side, bg=uk.BG_SIDEBAR)
        brand.pack(fill="x", padx=uk.dp(14), pady=(uk.dp(16), uk.dp(12)))
        if os.path.exists(ICON_PNG):
            try:
                img = tk.PhotoImage(file=ICON_PNG).subsample(8, 8)
                self._brand_img = img
                tk.Label(brand, image=img, bg=uk.BG_SIDEBAR).pack(
                    side="left", padx=(0, uk.dp(8)))
            except tk.TclError:
                pass
        box = tk.Frame(brand, bg=uk.BG_SIDEBAR)
        box.pack(side="left")
        tk.Label(box, text="内网穿透助手", font=uk.ui_font(12, "bold"),
                 bg=uk.BG_SIDEBAR, fg=uk.TEXT).pack(anchor="w")
        tk.Label(box, text="FRP · v" + about.APP_VERSION, font=uk.ui_font(10),
                 bg=uk.BG_SIDEBAR, fg=uk.TEXT_MUTED).pack(anchor="w")
        tk.Frame(side, bg=uk.BORDER_SOFT, height=1).pack(
            fill="x", padx=uk.dp(14), pady=(0, uk.dp(8)))

        # 导航
        nav = tk.Frame(side, bg=uk.BG_SIDEBAR)
        nav.pack(fill="x")
        for key, text, icon in (
            ("home", "首页", uk.ICONS["home"]),
            ("server", "服务端", uk.ICONS["server"]),
            ("client", "客户端", uk.ICONS["client"]),
            ("rules", "过滤规则", uk.ICONS["rules"]),
            ("log", "运行日志", uk.ICONS["log"]),
            ("about", "关于", uk.ICONS["about"]),
        ):
            item = uk.NavItem(nav, key, text, icon, self.show_page)
            item.pack(fill="x", padx=uk.dp(8), pady=1)
            self._nav_items[key] = item

        # 侧边栏底部：运行状态小灯（常驻，切到哪一页都看得到）
        self.side_status = tk.Frame(side, bg=uk.BG_SIDEBAR)
        self.side_status.pack(side="bottom", fill="x", padx=uk.dp(14),
                              pady=uk.dp(12))
        tk.Frame(side, bg=uk.BORDER_SOFT, height=1).pack(
            side="bottom", fill="x", padx=uk.dp(14))
        self.dot_server = tk.Label(self.side_status, text="●  服务端未运行",
                                   font=uk.ui_font(10), bg=uk.BG_SIDEBAR,
                                   fg=uk.TEXT_MUTED, anchor="w")
        self.dot_server.pack(fill="x")
        self.dot_client = tk.Label(self.side_status, text="●  客户端未运行",
                                   font=uk.ui_font(10), bg=uk.BG_SIDEBAR,
                                   fg=uk.TEXT_MUTED, anchor="w")
        self.dot_client.pack(fill="x")

        # 内容区
        self.content = tk.Frame(self, bg=uk.BG_PAGE)
        self.content.pack(side="left", fill="both", expand=True)

        # ★ 滚轮：绑在顶层窗口上统一分发。
        #   不能只绑在 Canvas 上 —— 滚轮事件是发给"鼠标下面那个控件"的，
        #   内容区里全是 Label/Frame，Canvas 根本收不到，
        #   结果就是"必须拖滚动条才能滚"。
        self.bind_all("<MouseWheel>", self._on_wheel, add="+")

    def _on_wheel(self, event):
        """把滚轮事件路由给"鼠标当前所在的那个可滚动页面"。"""
        if self._current_page is None:
            return
        area = self._scroll_areas.get(self._current_page)
        if not area:
            return
        canvas, inner = area
        try:
            if not canvas.winfo_ismapped():
                return
            # 用鼠标的屏幕坐标判断在不在这个区域内 ——
            # 比依赖 event.widget（可能是任意子控件）可靠得多
            px, py = self.winfo_pointerxy()
            x0, y0 = canvas.winfo_rootx(), canvas.winfo_rooty()
            x1, y1 = x0 + canvas.winfo_width(), y0 + canvas.winfo_height()
            if not (x0 <= px <= x1 and y0 <= py <= y1):
                return
            # 内容没超出可视区就不滚，免得"没得滚还抖一下"
            if inner.winfo_reqheight() <= canvas.winfo_height():
                return
        except tk.TclError:
            return
        step = -3 if event.delta > 0 else 3
        canvas.yview_scroll(step, "units")

    # ---------------- 页面注册 ----------------
    def _build_pages(self):
        builders = {
            "home": self._page_home,
            "server": self._page_server,
            "client": self._page_client,
            "rules": self._page_rules,
            "log": self._page_log,
            "about": self._page_about,
        }
        for key, builder in builders.items():
            frame = tk.Frame(self.content, bg=uk.BG_PAGE)
            self._pages[key] = frame
            builder(frame)

    def show_page(self, key: str):
        if key not in self._pages or self._current_page == key:
            return
        for k, f in self._pages.items():
            if k == key:
                f.pack(fill="both", expand=True)
            else:
                f.pack_forget()
        for k, item in self._nav_items.items():
            item.set_active(k == key)
        self._current_page = key
        if key == "rules":
            self._render_rules()
        elif key == "home":
            self._refresh_server_card()

    # ---------------- 可滚动的页面容器 ----------------
    def _scroll_area(self, parent, key: str):
        """返回一个可滚动的内层 Frame，并登记到 _scroll_areas 供滚轮路由。

        tkinter 没有现成的滚动容器，标准做法是
        Canvas + 内嵌 Frame + Scrollbar 三件套。
        """
        outer = tk.Frame(parent, bg=uk.BG_PAGE)
        outer.pack(fill="both", expand=True, padx=uk.dp(18), pady=uk.dp(16))

        canvas = tk.Canvas(outer, bg=uk.BG_PAGE, highlightthickness=0, bd=0)
        bar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview,
                            style="Vertical.TScrollbar")
        canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=uk.BG_PAGE)
        win = canvas.create_window(0, 0, window=inner, anchor="nw")

        def _on_inner(_e=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas(e):
            canvas.itemconfigure(win, width=e.width)

        inner.bind("<Configure>", _on_inner)
        canvas.bind("<Configure>", _on_canvas)

        self._scroll_areas[key] = (canvas, inner)
        return inner

    # ==================================================================
    # 页面：首页
    # ==================================================================
    def _page_home(self, parent):
        page = self._scroll_area(parent, "home")

        head = tk.Frame(page, bg=uk.BG_PAGE)
        head.pack(fill="x", pady=(0, 10))
        tk.Label(head, text="首页", font=uk.ui_font(16, "bold"),
                 bg=uk.BG_PAGE, fg=uk.TEXT).pack(side="left")
        tk.Label(head, text="实时掌握隧道流量与服务器状态", font=uk.ui_font(10),
                 bg=uk.BG_PAGE, fg=uk.TEXT_MUTED).pack(side="left", padx=(10, 0),
                                                       pady=(4, 0))
        uk.make_button(head, "重新检测服务器", self._refresh_server_card,
                       kind="ghost", bg=uk.BG_PAGE).pack(side="right")

        # ---- 运行状态 ----
        status = uk.Card(page, title="运行状态", icon=uk.ICONS["bolt"])
        status.pack(fill="x", pady=(0, uk.GAP))
        row = tk.Frame(status.body, bg=uk.BG_CARD)
        row.pack(fill="x")
        for i in range(4):
            row.columnconfigure(i, weight=1, uniform="st")
        self.tile_server = uk.StatTile(row, "服务端", "未运行",
                                       icon=uk.ICONS["server"], color=uk.TEXT_MUTED)
        self.tile_server.grid(row=0, column=0, sticky="w")
        self.tile_client = uk.StatTile(row, "客户端", "未运行",
                                       icon=uk.ICONS["client"], color=uk.TEXT_MUTED)
        self.tile_client.grid(row=0, column=1, sticky="w")
        self.tile_uptime = uk.StatTile(row, "已运行", "—",
                                       icon=uk.ICONS["ring"], color=uk.TEXT_SUB)
        self.tile_uptime.grid(row=0, column=2, sticky="w")
        self.tile_conns = uk.StatTile(row, "活跃连接", "0", unit="条",
                                      icon=uk.ICONS["link"], color=uk.ACCENT,
                                      sub="峰值 0")
        self.tile_conns.grid(row=0, column=3, sticky="w")

        # ---- 流量统计 ----
        flow = uk.Card(page, title="流量统计", icon=uk.ICONS["traffic"])
        flow.pack(fill="x", pady=(0, uk.GAP))

        ctl = tk.Frame(flow.body, bg=uk.BG_CARD)
        ctl.pack(fill="x", pady=(0, 6))
        self.flow_source = tk.StringVar(value="server")
        self._seg = {}
        seg = tk.Frame(ctl, bg=uk.BG_SOFT)
        seg.pack(side="left")
        for key, text in (("server", "服务端视角"), ("client", "客户端视角")):
            b = tk.Label(seg, text=text, font=uk.ui_font(10), bg=uk.BG_SOFT,
                         fg=uk.TEXT_SUB, padx=12, pady=5, cursor="hand2")
            b.pack(side="left", padx=2, pady=2)
            b.bind("<Button-1>", lambda _e, k=key: self._set_flow_source(k))
            self._seg[key] = b
        self._set_flow_source("server", force=True)
        tk.Label(ctl, text="图表保留最近 90 秒，鼠标悬停可看该点数值",
                 font=uk.ui_font(9), bg=uk.BG_CARD,
                 fg=uk.TEXT_MUTED).pack(side="left", padx=(12, 0))

        self.chart = uk.TrafficChart(flow.body, height=170)
        self.chart.pack(fill="x", pady=(4, 12))

        tiles = tk.Frame(flow.body, bg=uk.BG_CARD)
        tiles.pack(fill="x")
        for i in range(4):
            tiles.columnconfigure(i, weight=1, uniform="ft")
        self.t_up_speed = uk.StatTile(tiles, "上传速度", "0 B/s",
                                      icon=uk.ICONS["up"], color=uk.UP)
        self.t_up_speed.grid(row=0, column=0, sticky="w")
        self.t_down_speed = uk.StatTile(tiles, "下载速度", "0 B/s",
                                        icon=uk.ICONS["down"], color=uk.DOWN)
        self.t_down_speed.grid(row=0, column=1, sticky="w")
        # 峰值：只统计图上这段窗口内的最大速率（老数据滚出视野，峰值也跟着退）
        self.t_up_peak = uk.StatTile(tiles, "峰值上传", "0 B/s",
                                     icon=uk.ICONS["bolt"], color=uk.UP,
                                     sub="近 90 秒最高")
        self.t_up_peak.grid(row=0, column=2, sticky="w")
        self.t_down_peak = uk.StatTile(tiles, "峰值下载", "0 B/s",
                                       icon=uk.ICONS["bolt"], color=uk.DOWN,
                                       sub="近 90 秒最高")
        self.t_down_peak.grid(row=0, column=3, sticky="w")
        self.t_up_total = uk.StatTile(tiles, "累计上传", "0 B",
                                      icon=uk.ICONS["up"], color=uk.TEXT,
                                      sub="本次运行")
        self.t_up_total.grid(row=1, column=0, sticky="w", pady=(uk.dp(14), 0))
        self.t_down_total = uk.StatTile(tiles, "累计下载", "0 B",
                                        icon=uk.ICONS["down"], color=uk.TEXT,
                                        sub="本次运行")
        self.t_down_total.grid(row=1, column=1, sticky="w", pady=(uk.dp(14), 0))
        self.t_forward_total = uk.StatTile(tiles, "总转发量", "0 B",
                                           sub="上下行合计")
        self.t_forward_total.grid(row=1, column=2, sticky="w",
                                  pady=(uk.dp(14), 0))
        self.t_tunnels = uk.StatTile(tiles, "累计隧道", "0", unit="条",
                                     sub="被规则拦截 0 次")
        self.t_tunnels.grid(row=1, column=3, sticky="w", pady=(uk.dp(14), 0))

        # ---- 谁在用隧道（活跃连接明细）----
        conn_card = uk.Card(page, title="谁在用隧道", icon=uk.ICONS["link"])
        conn_card.pack(fill="x", pady=(0, uk.GAP))
        head = tk.Frame(conn_card.body, bg=uk.BG_CARD)
        head.pack(fill="x")
        self.conn_summary = tk.Label(head, text="当前没有活跃连接",
                                     font=uk.ui_font(11), bg=uk.BG_CARD,
                                     fg=uk.TEXT_SUB, anchor="w")
        self.conn_summary.pack(side="left")
        self.conn_owner = tk.Label(head, text="", font=uk.ui_font(10),
                                   bg=uk.BG_CARD, fg=uk.TEXT_MUTED, anchor="e")
        self.conn_owner.pack(side="right")
        self.conn_box = tk.Frame(conn_card.body, bg=uk.BG_CARD)
        self.conn_box.pack(fill="x", pady=(uk.dp(8), 0))
        _hint(conn_card.body,
              "「服务端视角」看到的是外部访问者的地址；"
              "「客户端视角」看到的是本机被穿透的服务。"
              "右侧的程序名由本机端口反查得到 —— 只有目标在本机时才查得到。")

        # ---- 服务器信息 ----
        self.card_server = uk.Card(page, title="服务器信息", icon=uk.ICONS["server"])
        self.card_server.pack(fill="x", pady=(0, uk.GAP))
        srv = self.card_server.body

        top = tk.Frame(srv, bg=uk.BG_CARD)
        top.pack(fill="x")
        for i in range(4):
            top.columnconfigure(i, weight=1, uniform="sv")
        self.s_host = uk.StatTile(top, "服务器地址", "—", color=uk.TEXT)
        self.s_host.grid(row=0, column=0, sticky="w")
        self.s_ip = uk.StatTile(top, "解析 IP", "—", color=uk.TEXT)
        self.s_ip.grid(row=0, column=1, sticky="w")
        self.s_latency = uk.StatTile(top, "连接延迟", "—", color=uk.TEXT_SUB)
        self.s_latency.grid(row=0, column=2, sticky="w")
        self.s_kind = uk.StatTile(top, "地址类型", "—", color=uk.TEXT_SUB)
        self.s_kind.grid(row=0, column=3, sticky="w")

        line = tk.Frame(srv, bg=uk.BG_SOFT)
        line.pack(fill="x", pady=(14, 0))
        self.s_geo_icon = tk.Label(line, text=uk.ICONS["ring"],
                                   font=uk.ui_font(11), bg=uk.BG_SOFT, fg=uk.ACCENT)
        self.s_geo_icon.pack(side="left", padx=(12, 6), pady=10)
        box = tk.Frame(line, bg=uk.BG_SOFT)
        box.pack(side="left", fill="x", expand=True, pady=8)
        tk.Label(box, text="IP 归属地", font=uk.ui_font(9), bg=uk.BG_SOFT,
                 fg=uk.TEXT_MUTED, anchor="w").pack(fill="x")
        self.s_geo = tk.Label(box, text="未检测（启动客户端后自动获取）",
                              font=uk.ui_font(11), bg=uk.BG_SOFT,
                              fg=uk.TEXT_SUB, anchor="w")
        self.s_geo.pack(fill="x")
        self.s_geo_src = tk.Label(line, text="", font=uk.ui_font(9),
                                  bg=uk.BG_SOFT, fg=uk.TEXT_MUTED)
        self.s_geo_src.pack(side="right", padx=12)

        _hint(srv, "归属地通过在线接口查询（会把服务器 IP 发给第三方）；"
                   "内网地址只做本地判断、不外发。结果本地缓存 30 天。")

    # ==================================================================
    # 页面：服务端
    # ==================================================================
    def _page_server(self, parent):
        page = self._scroll_area(parent, "server")
        tk.Label(page, text="服务端", font=uk.ui_font(16, "bold"),
                 bg=uk.BG_PAGE, fg=uk.TEXT).pack(anchor="w")
        tk.Label(page, text="在公网机器上开监听，等待内网客户端接入",
                 font=uk.ui_font(10), bg=uk.BG_PAGE,
                 fg=uk.TEXT_MUTED).pack(anchor="w", pady=(2, 10))

        card = uk.Card(page, title="监听设置", icon=uk.ICONS["server"])
        card.pack(fill="x", pady=(0, uk.GAP))

        self.sv_port = tk.StringVar(value="8800")
        self.sv_user_host = tk.StringVar(value="0.0.0.0")
        self.sv_cert_host = tk.StringVar(value="")
        self.sv_level = tk.StringVar(value="INFO")
        _field(card.body, "控制端口", self.sv_port, "供内网客户端连接（默认 8800）")
        _field(card.body, "对外监听地址", self.sv_user_host,
               "一般留 0.0.0.0 表示所有网卡")
        _field(card.body, "对外访问地址", self.sv_cert_host,
               "客户端连你时用的公网 IP 或域名（写进证书），可填多个、空格分隔；"
               "留空则只登记 localhost")
        _field(card.body, "日志级别", self.sv_level,
               "DEBUG / INFO / WARNING / ERROR")

        btns = tk.Frame(card.body, bg=uk.BG_CARD)
        btns.pack(fill="x", pady=(14, 0))
        self.sv_btn = uk.make_button(btns, "启动服务端", self._toggle_server)
        self.sv_btn.pack(side="left")
        uk.make_button(btns, "导出连接包（给客户端）", self._export_pack,
                       kind="ghost").pack(side="left", padx=8)
        self.sv_state = tk.Label(btns, text="未运行", font=uk.ui_font(10),
                                 bg=uk.BG_CARD, fg=uk.TEXT_MUTED)
        self.sv_state.pack(side="left", padx=12)

        _section(card.body, "首次启动会做什么")
        _bullet(card.body, "自动生成一套自签证书（certs/）与随机 token（tokens.txt）")
        _bullet(card.body, "证书里会写入上面填的「对外访问地址」；"
                           "地址变了会自动重签（CA 不变，客户端不用换包）")
        _bullet(card.body, "证书有效期 1 年，到期前自动续期（需 ca.key 在位）")
        _bullet(card.body, "点「导出连接包」把 ca.crt + token 打成 zip，"
                           "拷到内网机器导入即可")

        cert_card = uk.Card(page, title="凭据状态", icon=uk.ICONS["ring"])
        cert_card.pack(fill="x", pady=(0, uk.GAP))
        self.cert_info = tk.Label(cert_card.body, text="", font=uk.ui_font(10),
                                  bg=uk.BG_CARD, fg=uk.TEXT_SUB, justify="left",
                                  anchor="w")
        self.cert_info.pack(fill="x")
        self._refresh_cert_info()

    def _refresh_cert_info(self):
        if not hasattr(self, "cert_info"):
            return
        parts = []
        crt = os.path.join(CERT_DIR, "server.crt")
        if os.path.exists(crt):
            days = cert_days_left(crt)
            if days is not None:
                parts.append("服务端证书：剩余 %d 天%s"
                             % (days, "" if days > 30 else "（即将到期，会自动续期）"))
            else:
                parts.append("服务端证书：已存在（有效期读取失败）")
            # 把 SAN 亮出来：客户端连不上时，第一个要看的就是这里有没有那个地址。
            try:
                import gen_cert
                san = gen_cert.cert_san_hosts(crt)
            except Exception:           # noqa: BLE001
                san = []
            if san:
                parts.append("证书登记地址：%s" % "、".join(san))
            else:
                parts.append("证书登记地址：读取失败")
        else:
            parts.append("服务端证书：尚未生成（启动服务端时自动创建）")
        parts.append("数据目录：%s" % DATA_DIR)
        self.cert_info.configure(text="\n".join(parts))

    # ==================================================================
    # 页面：客户端
    # ==================================================================
    def _page_client(self, parent):
        page = self._scroll_area(parent, "client")
        tk.Label(page, text="客户端", font=uk.ui_font(16, "bold"),
                 bg=uk.BG_PAGE, fg=uk.TEXT).pack(anchor="w")
        tk.Label(page, text="把本机（内网）的服务，通过公网服务器暴露出去",
                 font=uk.ui_font(10), bg=uk.BG_PAGE,
                 fg=uk.TEXT_MUTED).pack(anchor="w", pady=(2, 10))

        card = uk.Card(page, title="连接设置", icon=uk.ICONS["client"])
        card.pack(fill="x", pady=(0, uk.GAP))

        self.cl_host = tk.StringVar()
        self.cl_port = tk.StringVar(value="8800")
        self.cl_local_host = tk.StringVar(value="127.0.0.1")
        self.cl_local_port = tk.StringVar(value="3389")
        self.cl_remote_port = tk.StringVar(value="9001")
        self.cl_name = tk.StringVar(value="myapp")
        self.cl_udp = tk.StringVar(value="")
        self.cl_level = tk.StringVar(value="INFO")

        _field(card.body, "服务器地址", self.cl_host, "公网服务端的 IP 或域名（必填）")
        _field(card.body, "服务器端口", self.cl_port, "与服务端「控制端口」一致")
        _field(card.body, "本机服务地址", self.cl_local_host, "被穿透的服务所在地址")
        _field(card.body, "本机服务端口", self.cl_local_port, "例：RDP=3389  Web=8080")
        _field(card.body, "对外端口", self.cl_remote_port, "外部访问时用的端口，如 9001")
        _field(card.body, "客户端名字", self.cl_name, "多客户端时须唯一，建议按用途命名")
        _field(card.body, "UDP 对外端口", self.cl_udp, "可选，填了才转发 UDP")

        # —— 证书主机名校验 ——
        # 默认关闭：服务端多在云主机上，公网 IP 是 NAT 映射、网卡上看不到，
        # 证书里往往只有 localhost。开启严格校验必然握手失败。
        # 关闭后仍然校验证书链（CA），只是不比对"证书里的地址"与"你连接的地址"。
        self.cl_strict_host = tk.BooleanVar(value=False)
        srow = tk.Frame(card.body, bg=uk.BG_CARD)
        srow.pack(fill="x", pady=(10, 0))
        tk.Label(srow, text="严格校验证书主机名", font=uk.ui_font(10),
                 bg=uk.BG_CARD, fg=uk.TEXT_SUB, width=12,
                 anchor="e").pack(side="left")
        uk.make_switch(srow, self.cl_strict_host).pack(side="left", padx=(8, 10))
        tk.Label(srow, text="关闭时仍校验 CA 链，只跳过「证书地址 vs 连接地址」比对",
                 font=uk.ui_font(9), bg=uk.BG_CARD,
                 fg=uk.TEXT_MUTED).pack(side="left")

        btns = tk.Frame(card.body, bg=uk.BG_CARD)
        btns.pack(fill="x", pady=(14, 0))
        self.cl_btn = uk.make_button(btns, "启动客户端", self._toggle_client)
        self.cl_btn.pack(side="left")
        uk.make_button(btns, "导入连接包", self._import_pack,
                       kind="ghost").pack(side="left", padx=8)
        self.cl_state = tk.Label(btns, text="未运行", font=uk.ui_font(10),
                                 bg=uk.BG_CARD, fg=uk.TEXT_MUTED)
        self.cl_state.pack(side="left", padx=12)

        # 本机服务与规则判定
        self.local_card = uk.Card(page, title="本机服务与规则", icon=uk.ICONS["rules"])
        self.local_card.pack(fill="x", pady=(0, uk.GAP))
        self.local_info = tk.Label(self.local_card.body, text="",
                                   font=uk.ui_font(10), bg=uk.BG_CARD,
                                   fg=uk.TEXT_SUB, justify="left", anchor="w")
        self.local_info.pack(fill="x")

        # 改这几个框就重算规则判定 —— 用户不用点"启动"才知道被拦
        for var in (self.cl_local_host, self.cl_local_port):
            var.trace_add("write", lambda *_a: self._refresh_local_info())
        self._refresh_local_info()

    def _refresh_local_info(self):
        if not hasattr(self, "local_info"):
            return
        host = self.cl_local_host.get().strip() or "127.0.0.1"
        try:
            port = int(self.cl_local_port.get().strip() or 0)
        except ValueError:
            port = 0
        allowed, why = self.rules.check(host, port)
        mark = "允许转发" if allowed else "★ 已被规则拦截，不会转发"
        self.local_info.configure(
            text="目标：%s:%s\n判定：%s\n说明：%s\n规则集：%s" % (
                host, port, mark, why, self.rules.stats_line()),
            fg=uk.ERR if not allowed else uk.TEXT_SUB)

    # ==================================================================
    # 页面：过滤规则
    # ==================================================================
    def _page_rules(self, parent):
        page = self._scroll_area(parent, "rules")
        tk.Label(page, text="过滤规则", font=uk.ui_font(16, "bold"),
                 bg=uk.BG_PAGE, fg=uk.TEXT).pack(anchor="w")
        tk.Label(page, text="按规则放行或拒绝转发 —— "
                            "数据库、远程桌面这类服务不该直接暴露到公网",
                 font=uk.ui_font(10), bg=uk.BG_PAGE,
                 fg=uk.TEXT_MUTED).pack(anchor="w", pady=(2, 10))

        # ---- 总开关 + 默认策略 ----
        card = uk.Card(page, title="总开关与默认策略", icon=uk.ICONS["rules"])
        card.pack(fill="x", pady=(0, uk.GAP))

        row = tk.Frame(card.body, bg=uk.BG_CARD)
        row.pack(fill="x")
        tk.Label(row, text="启用过滤", font=uk.ui_font(11), bg=uk.BG_CARD,
                 fg=uk.TEXT).pack(side="left")
        self.rules_on = tk.BooleanVar(value=self.rules.enabled)
        self.rules_switch = uk.make_switch(row, self.rules_on,
                                           command=self._on_rules_toggle)
        self.rules_switch.pack(side="left", padx=10)
        self.rules_mode_label = tk.Label(row, text="", font=uk.ui_font(10),
                                         bg=uk.BG_CARD, fg=uk.TEXT_MUTED)
        self.rules_mode_label.pack(side="left", padx=6)

        # 默认策略：只在"没有任何规则命中"时兜底。
        # 用下拉而不是并排胶囊 —— 选项文案长，并排会把这一行挤满。
        row2 = tk.Frame(card.body, bg=uk.BG_CARD)
        row2.pack(fill="x", pady=(14, 0))
        tk.Label(row2, text="默认策略", font=uk.ui_font(10), bg=uk.BG_CARD,
                 fg=uk.TEXT_SUB).pack(side="left", padx=(0, 8))
        self.mode_select = uk.make_select(
            row2, options=MODE_OPTIONS, value=self.rules.mode,
            command=self._set_rule_mode, bg=uk.BG_CARD,
            color_map=MODE_COLORS, width=24)
        self.mode_select.pack(side="left")
        self._mode_labels = {}       # 旧版是并排胶囊，现在用下拉，留空兼容

        _hint(card.body,
              "默认策略只在「没有任何规则命中」时才起作用 —— 它管的是"
              "没写进列表的目标。\n"
              "· 默认放行：只拦住列表里标为「黑名单」的（适合只想禁掉几个危险端口）\n"
              "· 默认拒绝：只放行列表里标为「白名单」的（适合只准暴露 8080 这类场景）\n"
              "每条规则是拦还是放，由它自己那一行的「类型」下拉决定，与默认策略无关。")

        _section(card.body, "新增一条规则", pady=(16, 6))
        row3 = tk.Frame(card.body, bg=uk.BG_CARD)
        row3.pack(fill="x")
        tk.Label(row3, text="类型", font=uk.ui_font(10), bg=uk.BG_CARD,
                 fg=uk.TEXT_SUB).pack(side="left", padx=(0, 6))
        self.nr_action = tk.StringVar(value=rules_mod.ACTION_DENY)
        self.nr_action_select = uk.make_select(
            row3, options=ACTION_OPTIONS, value=rules_mod.ACTION_DENY,
            command=lambda k: self.nr_action.set(k), bg=uk.BG_CARD,
            color_map=ACTION_COLORS, width=7)
        self.nr_action_select.pack(side="left", padx=(0, 12))
        self.nr_host = tk.StringVar(value="*")
        self.nr_port = tk.StringVar(value="")
        self.nr_note = tk.StringVar(value="")
        for label, var, width in (("目标主机", self.nr_host, 14),
                                  ("端口", self.nr_port, 12),
                                  ("备注", self.nr_note, 18)):
            tk.Label(row3, text=label, font=uk.ui_font(10), bg=uk.BG_CARD,
                     fg=uk.TEXT_SUB).pack(side="left", padx=(0, 6))
            tk.Entry(row3, textvariable=var, width=width, font=uk.ui_font(10),
                     relief="flat", bg=uk.BG_SOFT, fg=uk.TEXT,
                     highlightthickness=1, highlightbackground=uk.BORDER,
                     highlightcolor=uk.ACCENT).pack(side="left", padx=(0, 12),
                                                     ipady=4)
        uk.make_button(row3, "添加规则", self._add_rule).pack(side="left")

        _hint(card.body,
              "写法：主机支持 * 通配（如 192.168.* 或 *）；端口支持单个 3389、"
              "区间 8000-9000、多个 80,443，或 * 表示任意。\n"
              "填 localhost 会被当作 127.0.0.1 处理 —— 免得两边写法不一致导致规则不生效。")

        # ---- 快捷添加 ----
        quick = uk.Card(page, title="常见高危端口（点一下即添加为「黑名单」规则）",
                        icon=uk.ICONS["bolt"])
        quick.pack(fill="x", pady=(0, uk.GAP))
        wrap = tk.Frame(quick.body, bg=uk.BG_CARD)
        wrap.pack(fill="x")
        for i, (port, note) in enumerate(rules_mod.RISKY_PRESETS):
            chip = tk.Label(wrap, text="%s %s" % (port, note), font=uk.ui_font(9),
                            bg=uk.BG_SOFT, fg=uk.TEXT_SUB, padx=8, pady=4,
                            cursor="hand2")
            chip.grid(row=i // 5, column=i % 5, sticky="w", padx=3, pady=3)
            chip.bind("<Button-1>",
                      lambda _e, p=port, n=note: self._add_rule_quick(p, n))
            chip.bind("<Enter>", lambda e: e.widget.configure(bg=uk.ERR_SOFT))
            chip.bind("<Leave>", lambda e: e.widget.configure(bg=uk.BG_SOFT))

        # ---- 规则列表 ----
        list_card = uk.Card(page, title="规则列表", icon=uk.ICONS["log"])
        list_card.pack(fill="x", pady=(0, uk.GAP))
        self.rules_box = tk.Frame(list_card.body, bg=uk.BG_CARD)
        self.rules_box.pack(fill="x")

        # ---- 试算：立刻确认规则是否按预期生效 ----
        trial = tk.Frame(list_card.body, bg=uk.BG_CARD)
        trial.pack(fill="x", pady=(12, 0))
        tk.Label(trial, text="试算", font=uk.ui_font(10, "bold"), bg=uk.BG_CARD,
                 fg=uk.TEXT).pack(side="left", padx=(0, 8))
        self.try_host = tk.StringVar(value="127.0.0.1")
        self.try_port = tk.StringVar(value="")
        for label, var, width in (("主机", self.try_host, 14),
                                  ("端口", self.try_port, 8)):
            tk.Label(trial, text=label, font=uk.ui_font(10), bg=uk.BG_CARD,
                     fg=uk.TEXT_SUB).pack(side="left", padx=(0, 6))
            ent = tk.Entry(trial, textvariable=var, width=width,
                           font=uk.ui_font(10), relief="flat", bg=uk.BG_SOFT,
                           fg=uk.TEXT, highlightthickness=1,
                           highlightbackground=uk.BORDER,
                           highlightcolor=uk.ACCENT)
            ent.pack(side="left", padx=(0, 10), ipady=4)
            ent.bind("<Return>", lambda _e: self._try_rule())
        uk.make_button(trial, "试一下", self._try_rule, kind="ghost").pack(side="left")
        self.try_result = tk.Label(trial, text="改完规则后在这里试一下，立刻看到判定结果",
                                   font=uk.ui_font(10), bg=uk.BG_CARD,
                                   fg=uk.TEXT_MUTED, anchor="w")
        self.try_result.pack(side="left", padx=(12, 0))

        self.rules_summary = tk.Label(list_card.body, text="", font=uk.ui_font(9),
                                      bg=uk.BG_CARD, fg=uk.TEXT_MUTED, anchor="w",
                                      justify="left")
        self.rules_summary.pack(fill="x", pady=(10, 0))

        self._render_rules()


    def _render_rules(self):
        if not hasattr(self, "rules_box"):
            return
        for w in self.rules_box.winfo_children():
            w.destroy()

        self.rules_mode_label.configure(text=self.rules.stats_line())
        if hasattr(self, "rules_switch"):
            self.rules_switch.set_value(self.rules.enabled)
        if hasattr(self, "mode_select"):
            self.mode_select.set_value(self.rules.mode)

        if not self.rules.rules:
            tk.Label(self.rules_box,
                     text="还没有规则。可在上面填一条，或点下面的高危端口快速添加。",
                     font=uk.ui_font(10), bg=uk.BG_CARD, fg=uk.TEXT_MUTED,
                     anchor="w").pack(fill="x", pady=6)
        else:
            head = tk.Frame(self.rules_box, bg=uk.BG_CARD)
            head.pack(fill="x", pady=(0, 2))
            # 列宽与下面每行一一对应（类型列放下拉，见 make_select 的 width）
            for text, width in (("启用", 4), ("类型", 9),
                                ("目标", 21), ("备注", 0)):
                tk.Label(head, text=text, font=uk.ui_font(9), bg=uk.BG_CARD,
                         fg=uk.TEXT_MUTED, width=width if width else 0,
                         anchor="w").pack(side="left")
            for idx, r in enumerate(self.rules.rules):
                row = tk.Frame(self.rules_box, bg=uk.BG_SOFT)
                row.pack(fill="x", pady=1)

                var = tk.BooleanVar(value=r.enabled)
                tk.Checkbutton(row, variable=var, bg=uk.BG_SOFT,
                               activebackground=uk.BG_SOFT,
                               highlightthickness=0, bd=0,
                               command=lambda i=idx, v=var: self._toggle_rule(i, v.get())
                               ).pack(side="left", padx=(6, 0))

                # 这一行的类型下拉：换完立即写盘，后续新建隧道就按新类型判定
                sel = uk.make_select(
                    row, options=ACTION_OPTIONS, value=r.action,
                    command=lambda k, i=idx: self._set_rule_action(i, k),
                    bg=uk.BG_SOFT, color_map=ACTION_COLORS, width=7)
                sel.pack(side="left", padx=(0, 4), pady=2)

                tk.Label(row, text="%s : %s" % (r.host or "*", r.port or "*"),
                         font=uk.mono_font(10), bg=uk.BG_SOFT, fg=uk.TEXT,
                         width=21, anchor="w").pack(side="left", padx=(4, 4))
                tk.Label(row, text=r.note or "", font=uk.ui_font(10), bg=uk.BG_SOFT,
                         fg=uk.TEXT_MUTED, anchor="w").pack(side="left", fill="x",
                                                           expand=True)
                del_btn = tk.Label(row, text="删除", font=uk.ui_font(9),
                                   bg=uk.BG_SOFT, fg=uk.ERR, cursor="hand2",
                                   padx=10, pady=4)
                del_btn.pack(side="right", padx=4)
                del_btn.bind("<Button-1>", lambda _e, i=idx: self._del_rule(i))
                del_btn.bind("<Enter>", lambda e: e.widget.configure(bg=uk.ERR_SOFT))
                del_btn.bind("<Leave>", lambda e: e.widget.configure(bg=uk.BG_SOFT))

        deny, allow = self.rules.counts()
        self.rules_summary.configure(
            text="共 %d 条规则（黑名单 %d / 白名单 %d）· %s\n"
                 "判定顺序：拒绝优先 —— 命中黑名单就拒绝；否则命中白名单就放行；"
                 "都没命中按默认策略兜底。\n"
                 "规则改动对「之后新建的隧道」立即生效；已建立的连接不会被半路掐断。\n"
                 "配置文件：%s" % (len(self.rules.rules), deny, allow,
                                  self.rules.policy_label(), RULES_FILE))

    def _save_rules(self, reason: str = ""):
        try:
            self.rules.save(RULES_FILE)
        except OSError as exc:
            messagebox.showerror("保存失败", "无法写入规则文件：\n%s" % exc)
            return
        if reason:
            LOG.info("规则已更新（%s）：%s", reason, self.rules.stats_line())

    def _on_rules_toggle(self, value: bool):
        self.rules.enabled = value
        self._save_rules("总开关 %s" % ("开" if value else "关"))
        self._render_rules()
        self._refresh_local_info()

    def _set_rule_mode(self, mode: str):
        """改默认策略（未命中任何规则时的兜底动作）。"""
        self.rules.mode = mode
        self._save_rules("默认策略 → %s" % self.rules.policy_label())
        self._render_rules()
        self._refresh_local_info()

    def _set_rule_action(self, index: int, action: str):
        """把某条规则改成黑名单/白名单 —— 改完立即写盘，判定随之生效。"""
        if not self.rules.set_action(index, action):
            return
        r = self.rules.rules[index]
        self._save_rules("第 %d 条改为%s" % (index + 1, r.action_label()))
        self._render_rules()
        self._refresh_local_info()
        # 试算框里如果已经填了目标，顺手刷一下结果，立刻看到影响
        if hasattr(self, "try_port") and self.try_port.get().strip():
            self._try_rule()

    def _add_rule(self):
        host = self.nr_host.get().strip() or "*"
        port = self.nr_port.get().strip()
        note = self.nr_note.get().strip()
        action = self.nr_action_select.get() if hasattr(self, "nr_action_select") \
            else rules_mod.ACTION_DENY
        if not port:
            messagebox.showwarning("缺少端口",
                                   "请填写端口（如 3389）；想匹配全部端口就填 *。")
            return
        self.rules.add(host, port, note, action=action)
        self._save_rules("新增%s %s:%s" % (
            rules_mod.ACTION_LABEL.get(action, ""), host, port))
        self.nr_port.set("")
        self.nr_note.set("")
        self._render_rules()
        self._refresh_local_info()

    def _add_rule_quick(self, port: str, note: str):
        """快捷添加高危端口 —— 一律加为黑名单（拒绝）。

        旧版这里跟着全局模式走，白名单模式下点它就等于"放行高危端口"，
        与本意相反。现在固定为黑名单，不会再反过来。
        """
        if any(r.port == port and r.host in ("*", "") for r in self.rules.rules):
            LOG.info("规则已存在，跳过：*:%s", port)
            return
        self.rules.add("*", port, note, action=rules_mod.ACTION_DENY)
        self._save_rules("快捷添加黑名单 *:%s" % port)
        self._render_rules()
        self._refresh_local_info()

    def _toggle_rule(self, index: int, enabled: bool):
        if self.rules.set_enabled(index, enabled):
            self._save_rules("第 %d 条 %s" % (index + 1, "启用" if enabled else "停用"))
            self._render_rules()
            self._refresh_local_info()

    def _del_rule(self, index: int):
        if self.rules.remove(index):
            self._save_rules("删除一条")
            self._render_rules()
            self._refresh_local_info()

    def _try_rule(self):
        """试算某个 主机:端口 会怎么被处理 —— 让"规则是否生效"看得见。"""
        if not hasattr(self, "try_result"):
            return
        host = self.try_host.get().strip() or "127.0.0.1"
        raw = self.try_port.get().strip()
        try:
            port = int(raw)
        except ValueError:
            self.try_result.configure(text="→ 端口请填数字（如 3389）",
                                      fg=uk.WARN)
            return
        allowed, why = self.rules.check(host, port)
        if allowed:
            self.try_result.configure(text="→ 允许转发 · %s" % why, fg=uk.OK)
        else:
            self.try_result.configure(text="→ 拒绝转发 · %s" % why, fg=uk.ERR)


    # ==================================================================
    # 页面：日志
    # ==================================================================
    # 界面里保留的日志行数上限（超出后从头部丢）：够回溯当天，
    # 又不至于让 Text 控件变成"几万行卡死"的性能陷阱。
    LOG_VIEW_MAX_LINES = 5000

    def _page_log(self, parent):
        page = tk.Frame(parent, bg=uk.BG_PAGE)

        head = tk.Frame(page, bg=uk.BG_PAGE)
        head.pack(fill="x", padx=18, pady=(16, 8))
        tk.Label(head, text="运行日志", font=uk.ui_font(16, "bold"),
                 bg=uk.BG_PAGE, fg=uk.TEXT).pack(side="left")
        tk.Label(head, text="（保留最近 %d 天）" % LOG_RETAIN_DAYS,
                 font=uk.ui_font(10), bg=uk.BG_PAGE,
                 fg=uk.TEXT_MUTED).pack(side="left", padx=(8, 0))

        # 右侧一排操作按钮
        uk.make_button(head, "打开日志目录", self._open_log_dir, kind="ghost",
                       bg=uk.BG_PAGE).pack(side="right", padx=(6, 0))
        uk.make_button(head, "导出…", self._export_log, kind="ghost",
                       bg=uk.BG_PAGE).pack(side="right", padx=(6, 0))
        uk.make_button(head, "重新载入", self._reload_log_file, kind="ghost",
                       bg=uk.BG_PAGE).pack(side="right", padx=(6, 0))
        uk.make_button(head, "清空", self._clear_log, kind="ghost",
                       bg=uk.BG_PAGE).pack(side="right", padx=(6, 0))

        # 第二排：级别筛选 + 关键字过滤 + 自动滚动
        bar = tk.Frame(page, bg=uk.BG_PAGE)
        bar.pack(fill="x", padx=18, pady=(0, 8))
        tk.Label(bar, text="级别", font=uk.ui_font(10), bg=uk.BG_PAGE,
                 fg=uk.TEXT_SUB).pack(side="left")
        self.log_level = tk.StringVar(value="全部")
        lv_box = ttk.Combobox(bar, textvariable=self.log_level, width=8,
                              state="readonly",
                              values=("全部", "DEBUG", "INFO", "WARNING", "ERROR"),
                              font=uk.ui_font(10))
        lv_box.pack(side="left", padx=(6, 14))
        lv_box.bind("<<ComboboxSelected>>", lambda _e: self._reload_log_file())

        tk.Label(bar, text="搜索", font=uk.ui_font(10), bg=uk.BG_PAGE,
                 fg=uk.TEXT_SUB).pack(side="left")
        self.log_filter = tk.StringVar()
        ent = tk.Entry(bar, textvariable=self.log_filter, width=22,
                       font=uk.ui_font(10), relief="flat",
                       bg=uk.BG_SOFT, fg=uk.TEXT, insertbackground=uk.TEXT)
        ent.pack(side="left", padx=(6, 0), ipady=3)
        ent.bind("<Return>", lambda _e: self._reload_log_file())

        self.log_autoscroll = tk.BooleanVar(value=True)
        tk.Checkbutton(bar, text="自动滚动", variable=self.log_autoscroll,
                       bg=uk.BG_PAGE, activebackground=uk.BG_PAGE,
                       font=uk.ui_font(10), fg=uk.TEXT_SUB,
                       highlightthickness=0, bd=0,
                       selectcolor=uk.BG_PAGE).pack(side="right")
        self.log_count = tk.Label(bar, text="", font=uk.ui_font(9),
                                  bg=uk.BG_PAGE, fg=uk.TEXT_MUTED)
        self.log_count.pack(side="right", padx=(0, 12))

        wrap = tk.Frame(page, bg=uk.BG_PAGE)
        wrap.pack(fill="both", expand=True, padx=18, pady=(0, 16))
        self.log_text = tk.Text(wrap, wrap="none", bg="#1b2230", fg="#d7dde8",
                                insertbackground="#d7dde8", relief="flat",
                                font=uk.mono_font(10), padx=10, pady=8,
                                state="disabled", highlightthickness=0)
        yscroll = ttk.Scrollbar(wrap, orient="vertical",
                                command=self.log_text.yview,
                                style="Vertical.TScrollbar")
        self.log_text.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)
        self.log_text.tag_config("ERROR", foreground="#ff7b72")
        self.log_text.tag_config("WARNING", foreground="#e3b341")
        self.log_text.tag_config("INFO", foreground="#d7dde8")
        self.log_text.tag_config("DEBUG", foreground="#7d8799")

        # 首次进页面就把最近 7 天的历史读进来 —— 否则"刚打开是空白的"
        # 会被当成"日志不显示"（这正是用户反馈的现象）。
        self._reload_log_file()

    # ==================================================================
    # 页面：关于
    # ==================================================================
    def _page_about(self, parent):
        page = self._scroll_area(parent, "about")
        tk.Label(page, text="关于", font=uk.ui_font(16, "bold"),
                 bg=uk.BG_PAGE, fg=uk.TEXT).pack(anchor="w", pady=(0, 10))

        card = uk.Card(page, title=about.APP_NAME, icon=uk.ICONS["about"])
        card.pack(fill="x", pady=(0, uk.GAP))
        tk.Label(card.body, text="版本 %s" % about.APP_VERSION, font=uk.ui_font(10),
                 bg=uk.BG_CARD, fg=uk.TEXT_MUTED).pack(anchor="w")
        tk.Label(card.body, text=about.APP_DESCRIPTION, font=uk.ui_font(11),
                 bg=uk.BG_CARD, fg=uk.TEXT_SUB, wraplength=640,
                 justify="left").pack(anchor="w", pady=(6, 14))

        tk.Frame(card.body, bg=uk.BORDER_SOFT, height=1).pack(fill="x", pady=(0, 12))
        tk.Label(card.body, text="作者信息", font=uk.ui_font(11, "bold"),
                 bg=uk.BG_CARD, fg=uk.TEXT).pack(anchor="w", pady=(0, 6))
        for label, value, target in (
            ("姓名", AUTHOR_NAME, None),
            ("邮箱", AUTHOR_EMAIL, "mailto:" + AUTHOR_EMAIL),
            ("主页", AUTHOR_HOMEPAGE, AUTHOR_HOMEPAGE),
        ):
            row = tk.Frame(card.body, bg=uk.BG_CARD)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label + "：", font=uk.ui_font(10), width=6, anchor="e",
                     bg=uk.BG_CARD, fg=uk.TEXT_SUB).pack(side="left")
            if target:
                make_link_label(row, value, target).pack(side="left")
            else:
                tk.Label(row, text=value, font=uk.ui_font(10), bg=uk.BG_CARD,
                         fg=uk.TEXT).pack(side="left")
        tk.Label(card.body, text="点蓝色文字即可打开浏览器 / 邮件客户端",
                 font=uk.ui_font(9), bg=uk.BG_CARD,
                 fg=uk.TEXT_MUTED).pack(anchor="w", pady=(10, 0))
        tk.Label(card.body, text=about.COPYRIGHT, font=uk.ui_font(9),
                 bg=uk.BG_CARD, fg=uk.TEXT_MUTED).pack(anchor="w", pady=(8, 0))

        path_card = uk.Card(page, title="文件位置", icon=uk.ICONS["log"])
        path_card.pack(fill="x", pady=(0, uk.GAP))
        for label, path in (("数据目录", DATA_DIR), ("证书目录", CERT_DIR),
                            ("token 文件", TOKEN_FILE), ("规则文件", RULES_FILE)):
            row = tk.Frame(path_card.body, bg=uk.BG_CARD)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, font=uk.ui_font(10), width=10, anchor="e",
                     bg=uk.BG_CARD, fg=uk.TEXT_SUB).pack(side="left")
            tk.Label(row, text=path, font=uk.mono_font(9), anchor="w",
                     bg=uk.BG_CARD, fg=uk.TEXT).pack(side="left", padx=8)
        _hint(path_card.body,
              "程序的数据目录就是 exe 所在目录 —— 拷贝 exe 时请把 certs/ 与 "
              "tokens.txt 一起拷过去，否则相当于换了一套身份，客户端会连不上。")

        # ---- 手机控制（鸿蒙 App）----
        mb_card = uk.Card(page, title="手机控制（鸿蒙 App）", icon=uk.ICONS["server"])
        mb_card.pack(fill="x", pady=(0, uk.GAP))

        row = tk.Frame(mb_card.body, bg=uk.BG_CARD)
        row.pack(fill="x", pady=(0, 6))
        tk.Label(row, text="接口地址", font=uk.ui_font(10), width=10, anchor="e",
                 bg=uk.BG_CARD, fg=uk.TEXT_SUB).pack(side="left")
        self.mb_url_label = tk.Label(row, text="未开启", font=uk.mono_font(10),
                                     anchor="w", bg=uk.BG_CARD, fg=uk.WARN)
        self.mb_url_label.pack(side="left", padx=8)
        uk.make_button(row, "复制令牌", self._copy_mobile_token, kind="ghost",
                       bg=uk.BG_CARD).pack(side="right")

        self.mb_state_label = tk.Label(mb_card.body, text="", font=uk.ui_font(9),
                                       bg=uk.BG_CARD, fg=uk.TEXT_MUTED, anchor="w",
                                       justify="left")
        self.mb_state_label.pack(anchor="w")

        _hint(mb_card.body,
              "鸿蒙系统不支持运行 Python，所以穿透引擎仍在本机运行，"
              "手机 App 作为「远程控制台」——可查看状态、流量、连接、最近 7 天日志，"
              "并远程启停服务、管理过滤规则。\n"
              "用法：在手机「内网穿透助手」App 的设置页，填入上面这个地址的 IP、"
              "端口与令牌即可。工程源码在 harmonyos/ 目录，用 DevEco Studio 构建。")
        self._paint_mobile_info()

    # ==================================================================
    # 手机控制接口（供鸿蒙 App 使用）
    # ==================================================================
    def _mobile_bridge(self):
        """构造手机接口的能力桥接对象（懒加载，首次调用时创建）。

        为什么每项都传"回调"而不是直接把自己的属性塞进去？
            mobile_api 跑在独立的 HTTP 线程里，读的是随时在变的运行时状态
            （服务是否在跑、连了多少条、速度多少）。
            传回调 = 每次请求都现取一次最新值，不会拿到过期快照。
        """
        import mobile_api
        if getattr(self, "_mb_bridge", None) is None:
            self._mb_bridge = mobile_api.ControlBridge(
                rules=self.rules,
                rules_file=RULES_FILE,
                log_dir=LOG_DIR,
                data_dir=DATA_DIR,
                start_server=self._mobile_start_server,
                stop_server=self._mobile_stop_server,
                start_client=self._mobile_start_client,
                stop_client=self._mobile_stop_client,
                stats_provider=self._mobile_stats,
                links_provider=self._mobile_links,
                info_provider=self._mobile_info,
                busy_provider=lambda: getattr(self, "_mobile_busy", False),
            )
        return self._mb_bridge

    def _mobile_stats(self) -> dict:
        """给手机接口用的统计（含界面算出来的实时速度与角色信息）。

        ★★ 线程安全（踩过两次坑，务必守住）：
          本方法由 HTTP 线程调用，**绝不能碰任何 tkinter 对象** ——
          StringVar.get()、控件.cget() 都会抛 "main thread is not in main loop"。
          （第一次踩的是 sv_clients.cget，第二次是 flow_source.get。）
          所以这里只读 _mobile_snap_cache：那是 _update_stats() 在主线程里
          每次刷新时存好的**纯 dict**。
        """
        snap = dict(self._mobile_snap_cache or {})
        if self.server_runner.running:
            snap["_role"] = "server"
            snap["_running"] = True
        elif self.client_runner.running:
            snap["_role"] = "client"
            snap["_running"] = True
        else:
            snap["_role"] = "idle"
            snap["_running"] = False
        snap["_speed_up"] = round(self._rate_up, 1)
        snap["_speed_down"] = round(self._rate_down, 1)
        snap["clients"] = self._clients_cached
        return snap

    def _mobile_links(self) -> list:
        """当前连接明细：优先取正在跑的那个实例的台账。"""
        for runner in (self.server_runner, self.client_runner):
            obj = runner.obj
            if obj is None:
                continue
            book = getattr(obj, "connections", None)
            if book is not None and hasattr(book, "snapshot"):
                with contextlib.suppress(Exception):
                    return book.snapshot()
        return []

    def _mobile_info(self) -> dict:
        """服务器信息（复用界面已经探测好的结果，不重复联网）。"""
        res = getattr(self, "_last_probe", None) or {}
        return {
            "public_ip": res.get("public_ip") or res.get("ip") or "",
            "geo": res.get("geo") or "",
            "isp": res.get("isp") or "",
            "latency": res.get("latency") or 0,
            "ports": res.get("ports") or [],
        }

    # 启停：手机端来的请求必须回到主线程执行
    # （tkinter 的控件操作只能在主线程，Runner 的启停会碰控件）
    def _mobile_start_server(self):
        self._mobile_busy = True
        try:
            self.after(0, self._start_server)
        finally:
            self._mobile_busy = False

    def _mobile_stop_server(self):
        # 停止时如果本就没跑，直接返回，避免按钮状态错乱
        if self.server_runner.running:
            self.after(0, self._toggle_server)

    def _mobile_start_client(self):
        self._mobile_busy = True
        try:
            self.after(0, self._start_client)
        finally:
            self._mobile_busy = False

    def _mobile_stop_client(self):
        if self.client_runner.running:
            self.after(0, self._toggle_client)

    def _start_mobile_api(self):
        """程序启动时自动开启手机控制接口。

        默认监听 0.0.0.0，这样手机才连得上（局域网内）。
        端口取 MOBILE_API_PORT，被占用时自动往后找一个空闲端口。
        想关掉：命令行加 --no-mobile-api。
        """
        import mobile_api
        bridge = self._mobile_bridge()
        for offset in range(12):
            srv = mobile_api.MobileApiServer(
                MOBILE_API_HOST, MOBILE_API_PORT + offset, bridge)
            if srv.start():
                self.mobile_api = srv
                self._paint_mobile_info()
                return
        LOG.warning("手机控制接口未能启动（端口被占用？），不影响电脑端使用")
        self.mobile_api = None

    def _paint_mobile_info(self):
        """把接口地址与令牌显示到「设置」页，方便照着填到手机里。"""
        if not hasattr(self, "mb_url_label"):
            return
        srv = getattr(self, "mobile_api", None)
        info = srv.info() if srv is not None else {"running": False}
        if info.get("running"):
            self.mb_url_label.configure(
                text="%s   （令牌：%s）" % (info["url"], info["token"]),
                fg=uk.OK)
            self.mb_state_label.configure(
                text=("接口已开启 · 手机与电脑需在同一局域网"
                      if info.get("lan") else "接口仅本机可访问"),
                fg=uk.TEXT_MUTED)
        else:
            self.mb_url_label.configure(text="未开启", fg=uk.WARN)
            self.mb_state_label.configure(text="", fg=uk.TEXT_MUTED)

    def _copy_mobile_token(self):
        srv = getattr(self, "mobile_api", None)
        if srv is None or not srv.running:
            return
        info = srv.info()
        self.clipboard_clear()
        self.clipboard_append(info["token"])
        LOG.info("访问令牌已复制到剪贴板")
        messagebox.showinfo("已复制", "访问令牌已复制：\n%s" % info["token"])

    # ==================================================================
    # 统计刷新
    # ==================================================================
    def _set_flow_source(self, key: str, force: bool = False):
        if not force and self.flow_source.get() == key:
            return
        self.flow_source.set(key)
        for k, lbl in self._seg.items():
            active = (k == key)
            lbl.configure(bg=uk.ACCENT if active else uk.BG_SOFT,
                          fg="#ffffff" if active else uk.TEXT_SUB,
                          font=uk.ui_font(10, "bold" if active else "normal"))
        # 换视角时把速率基线清掉，否则会算出一个巨大的瞬时速率
        self._last_snap = None
        self._last_ts = None
        if hasattr(self, "chart"):
            self.chart.clear()

    def _current_stats(self):
        runner = (self.server_runner if self.flow_source.get() == "server"
                  else self.client_runner)
        obj = runner.obj
        stats = getattr(obj, "stats", None) if obj is not None else None
        return stats.snapshot() if stats is not None else None

    def _tick_stats(self):
        try:
            self._update_stats()
        except Exception as exc:        # noqa: BLE001 界面刷新绝不能把程序带崩
            LOG.debug("统计刷新异常：%s", exc)
        finally:
            self.after(1000, self._tick_stats)

    def _update_stats(self):
        snap = self._current_stats()
        now = time.time()

        # 给手机接口留一份纯数据快照（HTTP 线程只读这里，不碰控件）
        self._mobile_snap_cache = dict(snap) if snap else {}

        if snap is None:
            self._rate_up = self._rate_down = 0.0
            self.chart.push(0, 0)
            self._paint_metrics(None)
        else:
            if self._last_snap is not None and self._last_ts:
                dt = max(0.05, now - self._last_ts)
                self._rate_up = max(0.0, (snap["bytes_up"]
                                          - self._last_snap["bytes_up"]) / dt)
                self._rate_down = max(0.0, (snap["bytes_down"]
                                            - self._last_snap["bytes_down"]) / dt)
            self._last_snap = snap
            self._last_ts = now
            self.chart.push(self._rate_up, self._rate_down)
            self._paint_metrics(snap)
        self.chart.redraw()
        self._refresh_connections()

        sv = self.server_runner.running
        cl = self.client_runner.running
        self.tile_server.set("运行中" if sv else "未运行",
                             color=uk.OK if sv else uk.TEXT_MUTED)
        self.tile_client.set("运行中" if cl else "未运行",
                             color=uk.OK if cl else uk.TEXT_MUTED)
        self.dot_server.configure(text="●  服务端运行中" if sv else "●  服务端未运行",
                                  fg=uk.OK if sv else uk.TEXT_MUTED)
        self.dot_client.configure(text="●  客户端运行中" if cl else "●  客户端未运行",
                                  fg=uk.OK if cl else uk.TEXT_MUTED)

        # 运行时长/连接数取"任意一个在跑的"来显示
        any_snap = None
        for runner in (self.server_runner, self.client_runner):
            obj = runner.obj
            if obj is not None and getattr(obj, "stats", None) is not None:
                any_snap = obj.stats.snapshot()
                break
        if any_snap:
            self.tile_uptime.set(format_duration(any_snap["uptime"]))
            self.tile_conns.set(str(any_snap["connections_active"]),
                                sub="峰值 %d" % any_snap["connections_peak"])
            # 主线程把需要的数据算好放进纯数据缓存，供手机接口（HTTP 线程）读取。
            # 客户端不由本机接入，所以"在线客户端数"只对服务端有意义。
            obj = self._stats_obj()
            sessions = getattr(obj, "sessions", None) if obj is not None else None
            self._clients_cached = len(sessions) if isinstance(sessions, dict) else 0
        else:
            self.tile_uptime.set("—")
            self.tile_conns.set("0", sub="峰值 0")
            self._clients_cached = 0

    def _stats_obj(self):
        """当前在跑的实例（优先服务端）。"""
        for runner in (self.server_runner, self.client_runner):
            if runner.running and runner.obj is not None:
                return runner.obj
        return None

    def _paint_metrics(self, snap):
        if snap is None:
            for tile in (self.t_up_speed, self.t_down_speed,
                         self.t_up_peak, self.t_down_peak):
                tile.set("0 B/s")
            for tile in (self.t_up_total, self.t_down_total,
                         self.t_forward_total):
                tile.set("0 B")
            self.t_tunnels.set("0", sub="被规则拦截 0 次")
            return
        self.t_up_speed.set(format_speed(self._rate_up))
        self.t_down_speed.set(format_speed(self._rate_down))
        # 峰值直接取图表窗口内的最大值 —— 图上看得到的高点，数字才对得上
        pk_up, pk_down = self.chart.peak
        self.t_up_peak.set(format_speed(pk_up))
        self.t_down_peak.set(format_speed(pk_down))
        self.t_up_total.set(format_bytes(snap["bytes_up"]))
        self.t_down_total.set(format_bytes(snap["bytes_down"]))
        self.t_forward_total.set(
            format_bytes(snap["bytes_forwarded"]),
            sub="上下行合计 %s" % format_bytes(snap["bytes_up"] + snap["bytes_down"]))
        self.t_tunnels.set(str(snap["tunnels_established"]),
                           sub="被规则拦截 %d 次" % snap["rules_blocked"])

    # ---------------- 谁在用隧道 ----------------
    def _current_registry(self):
        """取当前视角那一边的连接台账。"""
        runner = (self.server_runner if self.flow_source.get() == "server"
                  else self.client_runner)
        obj = runner.obj
        return getattr(obj, "connections", None) if obj is not None else None

    def _owner_of_target(self, target: str) -> str:
        """把 "127.0.0.1:3389" 这样的目标解析成 "某个程序 (PID)"。

        ★ 带缓存：反查要枚举本机整张 TCP 表，每秒查一次没必要；
          进程不会秒级变化，缓存 5 秒足够，也避免白耗 CPU。
        """
        host, _, port_text = (target or "").rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            return "—"
        key = (host, port)
        now = time.time()
        hit = self._owner_cache.get(key)
        if hit and now - hit[0] < 5.0:
            return hit[1]
        desc = netinfo.describe_endpoint_owner(host, port)
        self._owner_cache[key] = (now, desc)
        return desc

    def _refresh_connections(self):
        """刷新「谁在用隧道」列表。

        做法是"行复用"而不是每次清空重建：
        每秒重建一次控件会闪，而且焦点/滚动位置都会丢。
        这里以 cid 为键，已有的行只更新文字，没了的行才销毁。
        """
        if not hasattr(self, "conn_box"):
            return
        reg = self._current_registry()
        rows = reg.snapshot() if reg is not None else []

        self.conn_summary.configure(
            text=("当前没有活跃连接" if not rows
                  else "共 %d 条活跃连接" % len(rows)))

        # 顺手把"目标端口是谁在监听"显示在右上角 —— 这是用户问的
        # "哪些程序在用隧道"，只在本机目标时才有意义
        if rows and self.flow_source.get() == "client":
            targets = {r["target"] for r in rows}
            if len(targets) == 1:
                t = next(iter(targets))
                self.conn_owner.configure(
                    text="目标程序：%s" % self._owner_of_target(t))
            else:
                self.conn_owner.configure(text="%d 个不同目标" % len(targets))
        else:
            self.conn_owner.configure(text="")

        seen = set()
        for rec in rows:
            cid = rec["cid"]
            seen.add(cid)
            row = self._conn_rows.get(cid)
            if row is None:
                row = self._make_conn_row()
                self._conn_rows[cid] = row
            self._fill_conn_row(row, rec)

        for cid in list(self._conn_rows):
            if cid not in seen:
                self._conn_rows.pop(cid).destroy()

    def _make_conn_row(self):
        bg = uk.BG_SOFT
        row = tk.Frame(self.conn_box, bg=bg)
        row.pack(fill="x", pady=1)
        cells = {}
        for name, width, expand in (
            ("proxy", 14, False), ("peer", 22, True),
            ("traffic", 20, False), ("elapsed", 10, False),
        ):
            lbl = tk.Label(row, text="", font=uk.mono_font(10), bg=bg,
                           fg=uk.TEXT, anchor="w", width=width)
            lbl.pack(side="left", padx=uk.dp(8), pady=uk.dp(5),
                     fill="x" if expand else None)
            cells[name] = lbl
        row.cells = cells
        return row

    def _fill_conn_row(self, row, rec):
        c = row.cells
        c["proxy"].configure(text=uk.fit_text(rec["proxy"], 14))
        c["peer"].configure(text=uk.fit_text(rec["peer"], 24))
        c["traffic"].configure(
            text="↑%s ↓%s" % (format_bytes(rec["bytes_up"]),
                              format_bytes(rec["bytes_down"])))
        c["elapsed"].configure(text=format_duration(rec["elapsed"]))

    # ---------------- 服务器信息 ----------------
    def _refresh_server_card(self):
        """按当前客户端配置发起一次探测（DNS + 归属地 + 延迟）。"""
        host = self.cl_host.get().strip()
        try:
            port = int(self.cl_port.get().strip() or 0)
        except ValueError:
            port = 0

        if not host:
            self.s_host.set("—")
            self.s_ip.set("—")
            self.s_latency.set("—")
            self.s_kind.set("—")
            self.s_geo.configure(text="请先在「客户端」页填写服务器地址", fg=uk.TEXT_SUB)
            self.s_geo_src.configure(text="")
            return

        self.s_host.set(uk.fit_text(host, 18))
        if not self.probe.start(host, port):
            return                          # 已有探测在跑

        self.s_ip.set("查询中…")
        self.s_latency.set("探测中…")
        self.s_kind.set("—")
        self.s_geo.configure(text="正在查询归属地…", fg=uk.TEXT_SUB)
        self.s_geo_src.configure(text="")
        self.after(250, self._watch_probe)

    def _watch_probe(self):
        res = self.probe.poll()
        if res.get("state") == "running":
            self.after(250, self._watch_probe)
            return
        if not res:
            return

        # 存一份给手机接口用（_mobile_info 读取）。注意字段名与探测结果的对应关系。
        self._last_probe = {
            "ip": res.get("ip"),
            "public_ip": res.get("ip"),
            "kind": res.get("kind"),
            "latency": res.get("latency_ms"),
            "geo": (res.get("geo") or {}).get("location"),
            "isp": (res.get("geo") or {}).get("isp"),
        }

        ip = res.get("ip")
        self.s_ip.set(ip or "解析失败")
        if res.get("resolve_error"):
            self.s_geo.configure(text="解析失败：%s" % res["resolve_error"], fg=uk.ERR)
            self.s_latency.set("—")
            return

        self.s_kind.set(res.get("kind", "—"))

        ms = res.get("latency_ms")
        if ms is None:
            self.s_latency.set("不可达", color=uk.ERR,
                               sub=res.get("latency_error") or "无法连接")
        else:
            grade, color = netinfo.latency_grade(ms)
            self.s_latency.set("%.0f ms" % ms, color=color, sub=grade)

        geo = res.get("geo")
        if geo:
            self.s_geo.configure(text=geo.get("location") or "—", fg=uk.TEXT)
            src = geo.get("source", "")
            if geo.get("cached"):
                src += "（本地缓存）"
            self.s_geo_src.configure(text=src)
        else:
            self.s_geo.configure(
                text="归属地查询失败：%s" % (res.get("geo_error") or "未知原因"),
                fg=uk.WARN)
            self.s_geo_src.configure(text="")

    # ---------------- 日志 ----------------
    def _poll_logs(self):
        try:
            while True:
                level, text = self.log_queue.get_nowait()
                self._append_log(level, text)
        except queue.Empty:
            pass
        self.after(120, self._poll_logs)

    def _log_level_ok(self, level: str) -> bool:
        """当前级别筛选是否放行这条日志。"""
        want = getattr(self, "log_level", None)
        want = want.get() if want is not None else "全部"
        return want == "全部" or want == level

    def _log_text_ok(self, text: str) -> bool:
        """当前关键字过滤是否放行这条日志。"""
        kw = getattr(self, "log_filter", None)
        kw = (kw.get() if kw is not None else "").strip().lower()
        return (not kw) or (kw in text.lower())

    def _append_log(self, level: str, text: str):
        if not hasattr(self, "log_text"):
            return
        if not (self._log_level_ok(level) and self._log_text_ok(text)):
            return
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n",
                             level if level in ("ERROR", "WARNING", "INFO", "DEBUG")
                             else "INFO")
        if int(self.log_text.index("end-1c").split(".")[0]) > self.LOG_VIEW_MAX_LINES:
            self.log_text.delete("1.0", "1000.0")
        if self.log_autoscroll.get():
            self.log_text.see("end")
        self.log_text.configure(state="disabled")
        self._update_log_count()

    def _update_log_count(self):
        if not hasattr(self, "log_count"):
            return
        try:
            lines = int(self.log_text.index("end-1c").split(".")[0])
        except (ValueError, tk.TclError):
            return
        self.log_count.configure(text="界面显示 %d 行" % lines)

    def _clear_log(self):
        """只清界面，不动磁盘上的日志文件。

        刻意跟"清空文件"分开：日志文件是排查问题的依据，
        误点一下按钮就把它删了会很难受（要删可以点「打开日志目录」自己删）。
        """
        if not hasattr(self, "log_text"):
            return
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._update_log_count()

    # -------- 历史日志：读取 / 筛选 / 导出 --------
    def _iter_log_files(self):
        return _iter_log_files(LOG_DIR)

    def _read_recent_logs(self, max_lines: int = 2000) -> "list[str]":
        return _read_recent_logs_impl(LOG_DIR, max_lines)

    def _reload_log_file(self):
        """把最近 7 天的历史日志读进界面（应用当前级别与关键字筛选）。"""
        if not hasattr(self, "log_text"):
            return
        lines = self._read_recent_logs(self.LOG_VIEW_MAX_LINES)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        for raw in lines:
            text = raw.rstrip("\n")
            if not text:
                continue
            lv = self._level_of_line(text)
            if self._log_level_ok(lv) and self._log_text_ok(text):
                self.log_text.insert("end", text + "\n", lv)
        self.log_text.configure(state="disabled")
        if self.log_autoscroll.get():
            self.log_text.see("end")
        self._update_log_count()

    @staticmethod
    def _level_of_line(text: str) -> str:
        return level_of_line(text)

    def _export_log(self):
        """把最近 7 天的日志另存一份，方便发给别人排查。"""
        from tkinter import filedialog
        default = "内网穿透日志_%s.log" % time.strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="导出日志", defaultextension=".log",
            initialfile=default, filetypes=[("日志文件", "*.log"),
                                            ("文本文件", "*.txt"),
                                            ("所有文件", "*.*")])
        if not path:
            return
        try:
            lines = self._read_recent_logs(10_000_000)   # 不限行数，全导出
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(lines)
        except OSError as exc:
            messagebox.showerror("导出失败", "写入文件失败：%s" % exc)
            return
        LOG.info("日志已导出到 %s（%d 行）", path, len(lines))
        messagebox.showinfo("导出完成", "已导出 %d 行到：\n%s" % (len(lines), path))

    def _open_log_dir(self):
        """在资源管理器里打开日志目录。"""
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            os.startfile(LOG_DIR)       # noqa: S606 Windows 专有
        except OSError as exc:
            messagebox.showerror("打开失败", "无法打开日志目录：%s" % exc)

    # ==================================================================
    # 启停
    # ==================================================================
    def _parse_port(self, text: str, label: str):
        text = (text or "").strip()
        if not text.isdigit() or not (1 <= int(text) <= 65535):
            messagebox.showwarning("端口不合法",
                                   "%s 需要 1-65535 之间的整数，当前为：%r"
                                   % (label, text))
            return None
        return int(text)

    def _toggle_server(self):
        if self.server_runner.running:
            LOG.info("正在停止服务端……")
            self.sv_btn.set_state(True)
            self.server_runner.stop(on_stopped=self._server_stopped)
        else:
            self._start_server()

    def _start_server(self):
        port = self._parse_port(self.sv_port.get(), "控制端口")
        if port is None:
            return
        host = self.sv_user_host.get().strip() or "0.0.0.0"
        level = self.sv_level.get().strip().upper() or "INFO"
        # 用户在「对外访问地址」里填的公网 IP / 域名：它们会被写进证书 SAN，
        # 同时传给服务端做自动续期，避免续期后 SAN 退回 localhost。
        cert_hosts = _split_hosts(self.sv_cert_host.get())

        if not ensure_certs(cert_hosts, CERT_DIR, log=LOG.info):
            messagebox.showerror(
                "证书生成失败",
                "无法生成自签证书，请确认已安装 cryptography。\n"
                "（打包版已内置，源码运行需 pip install cryptography）")
            return
        if not cert_hosts:
            LOG.warning(
                "未填写「对外访问地址」：证书里只登记了 localhost/127.0.0.1。"
                "客户端若用公网 IP 连接，严格主机名校验会失败 —— "
                "建议填上公网 IP 或域名后重启服务端。")
        ensure_token(TOKEN_FILE, log=LOG.info)

        args = _Namespace(
            serve_host="0.0.0.0", serve_port=port, user_host=host,
            token="", token_file=TOKEN_FILE,
            cert_file=os.path.join(CERT_DIR, "server.crt"),
            key_file=os.path.join(CERT_DIR, "server.key"),
            ca_cert_file=os.path.join(CERT_DIR, "ca.crt"),
            ca_key_file=os.path.join(CERT_DIR, "ca.key"),
            cert_host=_cert_hosts(cert_hosts), cert_renew_days=30,
            max_conn_per_ip=20, max_active_conns=100, max_queued=50,
            udp_target_addr="", max_udp_sessions=512, udp_session_timeout=60,
            enable_p2p=True,
            log_level=level,
        )
        _set_level(level)
        LOG.info("启动服务端：监听 0.0.0.0:%d", port)
        self.server_runner.start(
            lambda: _run_server(args, self.server_runner.holder),
            on_stopped=self._server_stopped)
        self.sv_btn.set_text("停止服务端")
        self.sv_btn.set_state(False)
        self.sv_state.configure(text="运行中", fg=uk.OK)
        self._set_flow_source("server")
        self._refresh_cert_info()

    def _server_stopped(self):
        self.after(0, self._after_server_stopped)

    def _after_server_stopped(self):
        self.sv_btn.set_text("启动服务端")
        self.sv_btn.set_state(False)
        self.sv_state.configure(text="未运行", fg=uk.TEXT_MUTED)
        LOG.info("服务端已停止")

    def _toggle_client(self):
        if self.client_runner.running:
            LOG.info("正在停止客户端……")
            self.cl_btn.set_state(True)
            self.client_runner.stop(on_stopped=self._client_stopped)
        else:
            self._start_client()

    def _start_client(self):
        host = self.cl_host.get().strip()
        if not host:
            messagebox.showwarning("缺少服务器地址", "请先填写「服务器地址」。")
            return
        port = self._parse_port(self.cl_port.get(), "服务器端口")
        local_port = self._parse_port(self.cl_local_port.get(), "本机服务端口")
        remote_port = self._parse_port(self.cl_remote_port.get(), "对外端口")
        if port is None or local_port is None or remote_port is None:
            return
        udp_port = 0
        if self.cl_udp.get().strip():
            udp_port = self._parse_port(self.cl_udp.get(), "UDP 对外端口")
            if udp_port is None:
                return

        local_host = self.cl_local_host.get().strip() or "127.0.0.1"

        # ★ 启动前先按规则自检：被拦就明确告诉用户，别让他白等
        allowed, why = self.rules.check(local_host, local_port)
        if not allowed:
            if not messagebox.askyesno(
                    "被过滤规则拦截",
                    "当前规则会拒绝这条转发：\n\n    %s:%s\n    原因：%s\n\n"
                    "仍要启动吗？（启动后该端口不会被转发）"
                    % (local_host, local_port, why)):
                return

        # 客户端只认 ca.crt —— 不再在这里生成服务端证书（旧版会生成，
        # 那套证书对连接毫无用处，却会让人误以为"证书没问题"）。
        if not ensure_client_ca(CERT_DIR, log=LOG.info):
            messagebox.showerror(
                "缺少 CA 证书",
                "本机还没有 ca.crt，无法校验服务端身份。\n\n"
                "请在服务端点「导出连接包」，再回到这里点「导入连接包」。")
            return
        ensure_token(TOKEN_FILE, log=LOG.info)

        strict = bool(self.cl_strict_host.get())
        if strict:
            LOG.info("已开启严格主机名校验：若服务端证书里没有登记 %s，"
                     "握手会在 TLS 阶段失败（可在服务端「对外访问地址」里补上）", host)
        else:
            LOG.info("已关闭主机名校验（仍校验 CA 链）："
                     "适用于服务端使用自签证书、通过公网 IP 访问的场景")

        args = _Namespace(
            serve_host=host, serve_port=port,
            local_host=local_host, local_port=local_port,
            proxy_name=self.cl_name.get().strip() or "myapp",
            remote_port=remote_port,
            udp_port=udp_port, udp_local_port=udp_port or 0,
            p2p_timeout=3.0, enable_p2p=True,
            token="", token_file=TOKEN_FILE,
            ca_file=os.path.join(CERT_DIR, "ca.crt"),
            insecure=False, no_tls=False,
            no_verify_hostname=not strict,
            rules=self.rules,       # 同一个对象：界面上改规则后新建隧道即生效
            log_level=self.cl_level.get().strip().upper() or "INFO",
        )
        _set_level(args.log_level)
        LOG.info("启动客户端：%s:%d  →  本机 %s:%d  （对外端口 %d%s）",
                 host, port, local_host, local_port, remote_port,
                 "，UDP %d" % udp_port if udp_port else "")
        self.client_runner.start(
            lambda: _run_client(args, self.client_runner.holder),
            on_stopped=self._client_stopped)
        self.cl_btn.set_text("停止客户端")
        self.cl_btn.set_state(False)
        self.cl_state.configure(text="运行中", fg=uk.OK)
        self._set_flow_source("client")
        self._refresh_server_card()

    def _client_stopped(self):
        self.after(0, self._after_client_stopped)

    def _after_client_stopped(self):
        self.cl_btn.set_text("启动客户端")
        self.cl_btn.set_state(False)
        self.cl_state.configure(text="未运行", fg=uk.TEXT_MUTED)
        LOG.info("客户端已停止")

    # ==================================================================
    # 连接包导出 / 导入
    # ==================================================================
    def _export_pack(self):
        if not os.path.exists(os.path.join(CERT_DIR, "ca.crt")):
            messagebox.showwarning("尚未生成凭据",
                                   "请先启动一次服务端，让它生成证书与 token。")
            return
        ensure_token(TOKEN_FILE, log=LOG.info)
        path = filedialog.asksaveasfilename(
            title="导出连接包", defaultextension=".zip",
            initialfile="frp-连接包.zip", filetypes=[("ZIP 压缩包", "*.zip")])
        if not path:
            return
        import zipfile
        server_port = self.sv_port.get().strip() or "8800"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(os.path.join(CERT_DIR, "ca.crt"), "certs/ca.crt")
            z.write(TOKEN_FILE, "tokens.txt")
            z.writestr("连接说明.txt",
                       "本包内含客户端所需凭据：\n"
                       "  certs/ca.crt  —— 用于校验服务端身份\n"
                       "  tokens.txt    —— 与服务端一致的共享密钥\n\n"
                       "使用：在客户端的「导入连接包」里选择本压缩包即可自动配置。\n"
                       "服务端控制端口：%s\n" % server_port)
        LOG.info("连接包已导出：%s", path)
        messagebox.showinfo(
            "导出成功",
            "连接包已保存：\n%s\n\n请将它拷贝到内网机器的客户端里导入。" % path)

    def _import_pack(self):
        path = filedialog.askopenfilename(
            title="导入连接包", filetypes=[("ZIP 压缩包", "*.zip"),
                                          ("所有文件", "*.*")])
        if not path:
            return
        import zipfile
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                ca_member = next((n for n in names if n.endswith("ca.crt")), None)
                tk_member = next((n for n in names if n.endswith("tokens.txt")), None)
                if not ca_member or not tk_member:
                    messagebox.showerror("包内容不对",
                                         "压缩包里没有找到 ca.crt / tokens.txt。")
                    return
                os.makedirs(CERT_DIR, exist_ok=True)
                with z.open(ca_member) as src, \
                        open(os.path.join(CERT_DIR, "ca.crt"), "wb") as dst:
                    dst.write(src.read())
                with z.open(tk_member) as src, open(TOKEN_FILE, "wb") as dst:
                    dst.write(src.read())
        except zipfile.BadZipFile:
            messagebox.showerror("无法读取", "这不是一个有效的 ZIP 包。")
            return
        LOG.info("已导入连接包：%s", path)
        self._refresh_cert_info()
        messagebox.showinfo("导入成功",
                            "已导入 CA 证书与 token。\n"
                            "接下来填写「本机服务端口」与「对外端口」即可启动。")

    # ---------------- 托盘常驻 ----------------
    def _setup_tray(self):
        """启动托盘图标线程。失败也不影响主功能。"""
        try:
            import tray
        except ImportError as exc:
            LOG.warning("托盘模块不可用：%s", exc)
            self.tray = None
            return
        self.tray = tray.TrayIcon(
            ICON_ICO,
            tooltip=APP_TITLE,
            on_show=lambda: self.after(0, self.restore_from_tray),
            on_exit=lambda: self.after(0, self.quit_from_tray),
            marshal=lambda fn: self.after(0, fn),
        )
        if not self.tray.start():
            LOG.warning("托盘启动失败，最小化将保持普通窗口行为")
            self.tray = None

    def _setup_minimize_behaviour(self):
        # <Unmap> 在窗口被最小化/隐藏时触发，用它来接管"最小化"
        self.bind("<Unmap>", self._on_unmap)

    def _on_unmap(self, event):
        if event.widget is not self or self.tray is None:
            return
        if self.state() == "iconic":
            # 稍等一下再收：立刻 withdraw 有时会让任务栏按钮残留
            self.after(150, self.minimize_to_tray)

    def minimize_to_tray(self, notify: bool = False) -> None:
        """收进托盘 —— 窗口不见了，但服务继续在后台跑。"""
        if self.tray is None:
            return
        if not self.tray.visible:
            self.tray.show_icon()
        self.withdraw()
        if notify:
            self.tray.notify(APP_TITLE,
                             "已最小化到托盘，双击图标可唤回窗口。")
        LOG.info("已最小化到托盘（服务继续在后台运行）")

    def restore_from_tray(self) -> None:
        """从托盘唤回窗口。"""
        self.deiconify()
        with contextlib.suppress(tk.TclError):
            self.state("normal")
        self.lift()
        with contextlib.suppress(tk.TclError):
            self.focus_force()
        if self.tray is not None and not self._has_any_service():
            self.tray.hide_icon()

    def quit_from_tray(self) -> None:
        """托盘菜单里的「退出程序」—— 这里是真的退。"""
        self._really_quit = True
        self.on_close()

    def _has_any_service(self) -> bool:
        return self.server_runner.running or self.client_runner.running

    # ---------------- 关闭 ----------------
    def on_close(self):
        """关闭按钮的行为：
        · 有服务在跑 → 收进托盘继续后台运行（服务不能因为关窗口就断）
        · 什么都没跑 → 直接退出，不留"幽灵进程"
        · 托盘不可用 / 托盘菜单点了退出 → 走原来的确认流程
        """
        if (not getattr(self, "_really_quit", False) and self.tray is not None
                and self._has_any_service()):
            self.minimize_to_tray(notify=True)
            return

        if self._has_any_service():
            if not messagebox.askyesno("确认退出", "服务仍在运行，确定要退出吗？"):
                return
            self.server_runner.stop()
            self.client_runner.stop()

        if self.tray is not None:
            self.tray.stop()
        if getattr(self, "mobile_api", None) is not None:
            self.mobile_api.stop()           # 手机接口随程序一起收尾
        with contextlib.suppress(Exception):
            if self.probe.cache is not None:
                self.probe.cache.save()      # 归属地缓存落盘
        self.destroy()


# ======================================================================
# 七、辅助：轻量 args 容器 + 运行封装
# ======================================================================
class _Namespace:
    """一个能用属性访问的简单命名空间（替代 argparse.Namespace）。"""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def _set_level(level: str) -> None:
    lv = parse_log_level(level)
    for name in ("frps", "frpc"):
        logging.getLogger(name).setLevel(lv)


async def _run_server(args, holder) -> None:
    import frps
    server = frps.Frps(args)
    holder["obj"] = server          # 暴露给界面，用来读 Stats
    await server.start()


async def _run_client(args, holder) -> None:
    import frpc
    client = frpc.Frpc(args)
    holder["obj"] = client
    await client.start()


# ======================================================================
# 八、隐藏自检模式（--selftest）
# ======================================================================
async def _selftest() -> int:
    """在临时目录里跑一次完整穿透，验证程序本体是否完好。

    用途：exe 是图形程序，不方便自动化验证内部网络逻辑；
          这个开关能在命令行跑一次真实的内网穿透，几秒出结果。
    顺带验一下**方向性流量统计**是否真的在计数（新加的统计容易写错方向）。
    """
    import tempfile
    import frps   # noqa: F401
    import frpc   # noqa: F401

    tmp = tempfile.mkdtemp(prefix="frp-selftest-")
    cert_dir = os.path.join(tmp, "certs")
    os.makedirs(cert_dir, exist_ok=True)
    LOG.info("[selftest] 临时目录 %s", tmp)

    import gen_cert  # noqa: F401
    generate_certs(cert_dir, hosts=["localhost", "127.0.0.1"])
    tk_path = os.path.join(tmp, "tokens.txt")
    ensure_token(tk_path, log=LOG.info)

    async def _echo(reader, writer):
        try:
            data = await reader.read(64)
            writer.write(b"ECHO:" + data)
            await writer.drain()
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    local_srv = await asyncio.start_server(_echo, "127.0.0.1", 19991)

    sargs = _Namespace(
        serve_host="127.0.0.1", serve_port=19880, user_host="127.0.0.1",
        token="", token_file=tk_path,
        cert_file=os.path.join(cert_dir, "server.crt"),
        key_file=os.path.join(cert_dir, "server.key"),
        ca_cert_file=os.path.join(cert_dir, "ca.crt"),
        ca_key_file=os.path.join(cert_dir, "ca.key"),
        cert_host=["localhost", "127.0.0.1"], cert_renew_days=30,
        max_conn_per_ip=20, max_active_conns=100, max_queued=50,
        udp_target_addr="", max_udp_sessions=512, udp_session_timeout=60,
        enable_p2p=False, log_level="ERROR",
    )
    sh = {"obj": None}
    server_task = asyncio.create_task(_run_server(sargs, sh))
    await asyncio.sleep(0.4)
    server = sh["obj"]

    cargs = _Namespace(
        serve_host="localhost", serve_port=19880,
        local_host="127.0.0.1", local_port=19991,
        proxy_name="selftest", remote_port=19001,
        udp_port=0, udp_local_port=0, p2p_timeout=3.0, enable_p2p=False,
        token="", token_file=tk_path,
        ca_file=os.path.join(cert_dir, "ca.crt"),
        insecure=False, no_tls=False, log_level="ERROR",
    )
    ch = {"obj": None}
    client_task = asyncio.create_task(_run_client(cargs, ch))
    await asyncio.sleep(0.4)
    client = ch["obj"]

    ok = False
    try:
        for _ in range(150):
            if server is not None and server.sessions:
                break
            await asyncio.sleep(0.1)

        if server is None or not server.sessions:
            LOG.error("自检失败：客户端未能接入服务端")
        else:
            # ★ 用户端口是带 TLS 的，这里必须用 CA 建 SSLContext ——
            #   否则握手失败，表现是"连上了但收不到数据"，容易误判成转发坏了。
            import ssl as _ssl
            ctx = _ssl.create_default_context(cafile=os.path.join(cert_dir, "ca.crt"))
            reader, writer = await asyncio.open_connection("127.0.0.1", 19001, ssl=ctx)
            payload = b"hello-frp"
            writer.write(payload)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(64), timeout=10)
            writer.close()
            LOG.info("外部发出 %r → 收到 %r", payload, resp)
            if resp == b"ECHO:" + payload:
                ok = True
            else:
                LOG.error("自检失败：返回内容不符（期望 %r）", b"ECHO:" + payload)

            # 方向性统计校验
            s = client.stats.snapshot() if client is not None else {}
            up, down = s.get("bytes_up", 0), s.get("bytes_down", 0)
            total = s.get("bytes_forwarded", 0)
            LOG.info("[selftest] 流量统计：上行 %s 下行 %s 合计 %s",
                     format_bytes(up), format_bytes(down), format_bytes(total))
            if up == 0 or down == 0:
                LOG.error("自检失败：方向性统计没计数（上行=%d 下行=%d）", up, down)
                ok = False
            elif total != up + down:
                LOG.error("自检失败：合计 %d ≠ 上行+下行 %d", total, up + down)
                ok = False
    except Exception as exc:            # noqa: BLE001
        LOG.error("自检异常：%s", exc)
    finally:
        client_task.cancel()
        server_task.cancel()
        await asyncio.gather(client_task, server_task, return_exceptions=True)
        local_srv.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(local_srv.wait_closed(), timeout=1.0)
        import shutil as _sh
        _sh.rmtree(tmp, ignore_errors=True)

    if ok:
        print("SELFTEST: PASS")
        return 0
    print("SELFTEST: FAIL")
    return 1


# ======================================================================
# 九、入口
# ======================================================================
def build_about_dialog(parent: tk.Misc, center_on=None) -> tk.Toplevel:
    """简洁的「关于」窗口（给 --about 用；主界面里的「关于」页另有一套）。"""
    win = tk.Toplevel(parent)
    win.title("关于")
    if center_on is not None:
        win.transient(center_on)
    win.resizable(False, False)
    win.configure(bg=uk.BG_CARD)

    wrap = tk.Frame(win, bg=uk.BG_CARD, padx=22, pady=20)
    wrap.pack(fill="both", expand=True)

    tk.Label(wrap, text=about.APP_NAME, font=uk.ui_font(14, "bold"),
             bg=uk.BG_CARD, fg=uk.TEXT).pack(anchor="w")
    tk.Label(wrap, text="版本 %s" % about.APP_VERSION, font=uk.ui_font(10),
             bg=uk.BG_CARD, fg=uk.TEXT_MUTED).pack(anchor="w", pady=(2, 10))
    tk.Label(wrap, text=about.APP_DESCRIPTION, font=uk.ui_font(10),
             bg=uk.BG_CARD, fg=uk.TEXT_SUB, wraplength=380,
             justify="left").pack(anchor="w", pady=(0, 14))

    tk.Frame(wrap, bg=uk.BORDER_SOFT, height=1).pack(fill="x", pady=(0, 12))
    tk.Label(wrap, text="作者信息", font=uk.ui_font(11, "bold"),
             bg=uk.BG_CARD, fg=uk.TEXT).pack(anchor="w", pady=(0, 6))
    for label, value, target in (
        ("姓名", AUTHOR_NAME, None),
        ("邮箱", AUTHOR_EMAIL, "mailto:" + AUTHOR_EMAIL),
        ("主页", AUTHOR_HOMEPAGE, AUTHOR_HOMEPAGE),
    ):
        row = tk.Frame(wrap, bg=uk.BG_CARD)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=label + "：", font=uk.ui_font(10), width=6, anchor="e",
                 bg=uk.BG_CARD, fg=uk.TEXT_SUB).pack(side="left")
        if target:
            make_link_label(row, value, target).pack(side="left")
        else:
            tk.Label(row, text=value, font=uk.ui_font(10), bg=uk.BG_CARD,
                     fg=uk.TEXT).pack(side="left")

    tk.Label(wrap, text="点蓝色文字即可打开浏览器 / 邮件客户端",
             font=uk.ui_font(9), bg=uk.BG_CARD,
             fg=uk.TEXT_MUTED).pack(anchor="w", pady=(10, 0))
    tk.Label(wrap, text=about.COPYRIGHT, font=uk.ui_font(9), bg=uk.BG_CARD,
             fg=uk.TEXT_MUTED).pack(anchor="w", pady=(8, 12))

    uk.make_button(wrap, "关闭", win.destroy, kind="ghost",
                   bg=uk.BG_CARD).pack(anchor="e")

    win.update_idletasks()
    if center_on is not None:
        px, py = center_on.winfo_rootx(), center_on.winfo_rooty()
        pw, ph = center_on.winfo_width(), center_on.winfo_height()
    else:
        px, py, pw, ph = 240, 200, 800, 700
    w, h = win.winfo_width(), win.winfo_height()
    win.geometry("+%d+%d" % (px + (pw - w) // 2, py + (ph - h) // 3))
    win.focus_set()
    return win


def _show_about_window() -> int:
    """单独弹一个「关于」窗口（不启动主界面），用于 exe --about。"""
    root = tk.Tk()
    root.withdraw()
    apply_window_icon(root)
    style = ttk.Style(root)
    with contextlib.suppress(tk.TclError):
        style.theme_use("vista")

    win = build_about_dialog(root, center_on=None)
    win.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
    return 0


# 日志文件保留天数（按天轮转，滚动删除超过这个天数的旧文件）
LOG_RETAIN_DAYS = 7
LOG_FILE_NAME = "app.log"
LOG_DIR = os.path.join(DATA_DIR, "logs")


def _file_handler_for_today():
    """构造"按天轮转、保留 7 天"的文件 handler。

    为什么用 TimedRotatingFileHandler 而不是 RotatingFileHandler？
        原来按体积轮转（1MB×3 份），日志一多就只剩几分钟的记录，
        完全无法回溯"程序这几天到底干了什么"。
        改成按天轮转 + 保留 7 份 = **永远能看到最近 7 天的完整记录**，
        正好对上需求："日志要记录本程序 7 天的所有记录"。

    轮转规则：
        · 每天 0 点自动切一份，旧的改名为 app.log.YYYY-MM-DD；
        · 超过 7 天的自动删除；
        · 即使程序跨天不重启，到点也会切（delay=False 时由 handler 自己判断）。
    """
    from logging.handlers import TimedRotatingFileHandler
    os.makedirs(LOG_DIR, exist_ok=True)
    fh = TimedRotatingFileHandler(
        os.path.join(LOG_DIR, LOG_FILE_NAME),
        when="midnight", interval=1, backupCount=LOG_RETAIN_DAYS,
        encoding="utf-8", delay=True)
    # 让滚动出来的文件名是 app.log.2026-10-14 这种一眼能看懂的样子
    fh.suffix = "%Y-%m-%d"
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"))
    return fh


def _setup_file_logging():
    """让**所有** logger 的日志都写进 数据目录/logs/app.log（保留 7 天）。

    打包的 exe 是 windowed 模式（--noconsole）：没有控制台，终端日志
    在双击运行时等于扔掉了 —— 一旦出问题就完全没线索。写文件之后，
    用户（或作者）翻一眼日志就能定位，不用再猜。

    ★ 关键点（踩过的坑）：
      原来只把 handler 挂到 FILE_LOG_NAMES 里那几个具名 logger 上，
      而它们各自 propagate=False，于是**真正干活的 frp.protocol /
      frp.cert 以及后续新增模块的日志全被漏掉**。
      现在统一交给 protocol.install_logging() 逐个别名挂，
      新增模块只要把名字加进 protocol.NAMED_LOGGERS 即可。
    """
    try:
        fh = _file_handler_for_today()
        protocol.install_logging([fh], level=logging.DEBUG)
        return fh
    except OSError:
        return None     # 写不了日志文件也绝不能影响程序本身


def _iter_log_files(log_dir: str = None):
    """按时间倒序列出最近 7 天的日志文件（今天的排最前）。"""
    import glob
    log_dir = log_dir or LOG_DIR
    files = []
    today = os.path.join(log_dir, LOG_FILE_NAME)
    if os.path.exists(today):
        files.append(today)
    pat = os.path.join(log_dir, LOG_FILE_NAME + ".*")
    dated = [p for p in glob.glob(pat)
             if re.match(r"^\d{4}-\d{2}-\d{2}$",
                         os.path.basename(p)[len(LOG_FILE_NAME) + 1:])]
    dated.sort(reverse=True)
    files.extend(dated)
    return files


def _read_recent_logs_impl(log_dir: str, max_lines: int = 2000) -> "list[str]":
    """从最新的日志文件往前读，凑够 max_lines 行为止。

    从**文件尾部**读：日志是追加写的，最新的在最后，
    用户最关心的也是最近发生了什么，从头读会把关键信息挤掉。
    """
    out: "list[str]" = []
    for path in _iter_log_files(log_dir):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue
        out = lines + out
        if len(out) >= max_lines:
            out = out[-max_lines:]
            break
    return out


def level_of_line(text: str) -> str:
    """从一行日志里认出级别，用于着色与筛选。

    行格式：2026-10-14 15:31:19 [INFO] frps: xxxx
    """
    m = re.search(r"\[(DEBUG|INFO|WARNING|ERROR|CRITICAL)\]", text)
    if not m:
        return "INFO"
    lv = m.group(1)
    return "WARNING" if lv == "CRITICAL" else lv


def _prune_old_logs() -> int:
    """兜底清理：删掉超过 LOG_RETAIN_DAYS 天的 app.log.* 文件。

    TimedRotatingFileHandler 只在**发生轮转**时删旧文件；
    如果程序停了几天再打开，或者一天内没触发轮转，
    旧文件就可能一直留着。这里在启动时主动扫一遍，
    保证"只看最近 7 天"这个承诺在任何情况下都成立。
    """
    import glob
    import re
    cutoff = time.time() - LOG_RETAIN_DAYS * 86400
    removed = 0
    pattern = os.path.join(LOG_DIR, LOG_FILE_NAME + ".*")
    stamp = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    for path in glob.glob(pattern):
        suffix = os.path.basename(path)[len(LOG_FILE_NAME) + 1:]
        if not stamp.match(suffix):
            continue        # 不是日期后缀（比如 .log.1），不碰
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
        except OSError:
            pass
    return removed


def main() -> int:
    set_windows_app_id()
    # ★ DPI 感知必须在建窗口之前声明，否则 Windows 会把整个界面
    #   位图拉伸，字体发虚（见 ui_kit.enable_dpi_awareness 的说明）。
    uk.enable_dpi_awareness()
    _setup_file_logging()
    _prune_old_logs()

    # ---- 命令行参数（只做简单的存在性判断，不引 argparse）----
    global MOBILE_API_HOST, MOBILE_API_PORT
    if "--no-mobile-api" in sys.argv:
        os.environ["FRP_NO_MOBILE_API"] = "1"      # 关闭给鸿蒙 App 用的控制接口
    for i, a in enumerate(sys.argv):
        if a == "--mobile-api-port" and i + 1 < len(sys.argv):
            with contextlib.suppress(ValueError):
                MOBILE_API_PORT = int(sys.argv[i + 1])
        elif a == "--mobile-api-lan":
            # 显式要求监听局域网（默认已是 0.0.0.0，此参数保留以兼容旧习惯）
            MOBILE_API_HOST = "0.0.0.0"
        elif a == "--mobile-api-localhost":
            MOBILE_API_HOST = "127.0.0.1"          # 只允许本机访问，更安全

    if "--selftest" in sys.argv:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%H:%M:%S")
        return asyncio.run(_selftest())

    if "--about" in sys.argv or "-v" in sys.argv or "--version" in sys.argv:
        if sys.stdout is not None:
            with contextlib.suppress(Exception):
                print(about.summary())
                for _k, _v in about.author_lines():
                    print("  %s：%s" % (_k, _v))
        return _show_about_window()

    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
