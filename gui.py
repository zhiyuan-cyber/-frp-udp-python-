"""
gui.py —— 图形界面版 FRP（一个窗口搞定内网穿透）

为什么要有这个文件？
    命令行版要记十几个参数（--serve_host / --local_port / --token_file ...），
    对"只想过一次把内网端口暴露到公网"的人来说太重了。
    这里把它包成一个窗口：填几个框、点一下按钮就完事。

设计要点：
    1. 一个 exe 同时干两件事 —— 上面两个标签页，「服务端」和「客户端」，
       按需切一个启动即可（公网机器开服务端，内网机器开客户端）。
    2. 全自动 —— 首次运行自动生成证书（自签）和随机 token，不需要你懂 TLS。
       服务端和客户端各生成一份，**需把服务端的 tokens.txt 与 certs/ca.crt
       拷给客户端**（界面上有「导出连接包」按钮，一键拷好这两样）。
    3. 表单校验 + 实时日志 —— 填错有中文提示，运行日志滚动显示，一目了然。
    4. 界面不会卡 —— 网络逻辑跑在后台线程的 asyncio 事件循环里，
       日志经队列回传到界面线程渲染（tkinter 不是线程安全的，必须这么做）。

打包：
    python build_exe.py      # 见同目录 build_exe.py
"""

import asyncio
import contextlib
import logging
import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

# 让"打包成 exe 后"与"源码运行"都能正确 import 同目录的模块
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
    SRC_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    SRC_DIR = BASE_DIR

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

import protocol  # noqa: E402  （导入以触发 logger 初始化）
from protocol import (  # noqa: E402
    build_client_ssl_context,
    build_server_ssl_context,
    cert_days_left,
    get_logger,
    parse_log_level,
)
import about  # noqa: E402  （作者/程序信息集中在这里，改 about.py 全项目生效）

LOG = get_logger("gui", parse_log_level("INFO"))

# 数据目录：打包后放在 exe 旁边，源码运行时放在脚本旁边
DATA_DIR = BASE_DIR
CERT_DIR = os.path.join(DATA_DIR, "certs")
TOKEN_FILE = os.path.join(DATA_DIR, "tokens.txt")

# 窗口标题、作者信息统一取自 about.py，避免多处硬编码改漏
APP_TITLE = about.APP_TITLE
AUTHOR_NAME = about.AUTHOR_NAME
AUTHOR_EMAIL = about.AUTHOR_EMAIL
AUTHOR_HOMEPAGE = about.AUTHOR_HOMEPAGE


# ======================================================================
# 一、日志回传：让 logging 的输出同时进文件和控制台窗口
# ======================================================================
class QueueLogHandler(logging.Handler):
    """把日志记录塞进线程安全队列，由界面线程定期取出显示。

    为什么绕这一圈？因为 logging 是在后台线程里调用的，而 tkinter 控件
    只能从主线程操作 —— 直接跨线程写文本框会让程序随机崩溃。
    """

    def __init__(self, log_queue: "queue.Queue[tuple[str, str]]"):
        super().__init__()
        self.log_queue = log_queue
        self.setFormatter(
            logging.Formatter(fmt="%(asctime)s [%(levelname)s] %(message)s",
                              datefmt="%H:%M:%S")
        )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.log_queue.put((record.levelname, self.format(record)))
        except Exception:      # 日志本身不能反过来把程序搞崩
            pass


def install_gui_logging(log_queue: "queue.Queue[tuple[str, str]]") -> None:
    """把根 logger 的输出导向界面（原有控制台输出保留，方便排查）。"""
    handler = QueueLogHandler(log_queue)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    # 清掉 protocol.get_logger 默认挂的控制台 handler，避免重复打印
    for name in ("frps", "frpc", "gui", "protocol"):
        lg = logging.getLogger(name)
        lg.handlers = [handler]
        lg.propagate = False
        lg.setLevel(logging.DEBUG)


# ======================================================================
# 二、自动初始化：证书 + token（全自动，无需用户理解 TLS）
# ======================================================================
def ensure_certs(host: str, out_dir: str, log=print) -> bool:
    """没有证书就生成一套自签 CA + 服务端证书。

    直接复用 gen_cert.py 里的函数（而不是 subprocess 去调它），
    这样打包成 exe 后也能正常工作 —— exe 里没有独立的 gen_cert.py 可执行。
    """
    need = ["ca.crt", "ca.key", "server.crt", "server.key"]
    if all(os.path.exists(os.path.join(out_dir, f)) for f in need):
        log("证书已存在，跳过生成：%s" % out_dir)
        return True

    log("正在生成自签证书（首次运行需要几秒）……")
    os.makedirs(out_dir, exist_ok=True)

    # 延迟导入：没有 cryptography 时给出可读的中文提示，而不是一堆栈
    try:
        import gen_cert
    except ImportError as exc:
        log("无法生成证书：%s" % exc)
        return False

    hosts = [h for h in (host, "localhost", "127.0.0.1") if h]
    # 去重但保序
    seen, uniq = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            uniq.append(h)

    ca_key, ca_cert = gen_cert.build_ca()
    srv_key, srv_cert = gen_cert.build_server_cert(ca_key, ca_cert, uniq)

    # 复用 gen_cert 的落盘逻辑，保证与命令行版生成的文件完全一致
    gen_cert.write_pem(os.path.join(out_dir, "ca.crt"), ca_cert)
    gen_cert.write_pem(os.path.join(out_dir, "ca.key"), None, key=ca_key, key_only=True)
    gen_cert.write_pem(os.path.join(out_dir, "server.crt"), srv_cert)
    gen_cert.write_pem(os.path.join(out_dir, "server.key"), None,
                       key=srv_key, key_only=True)
    log("证书已生成：certs/（含 ca.crt，客户端需要它）")
    return True


def ensure_token(path: str, log=print) -> str:
    """没有 token 文件就生成一个强随机 token。返回主 token。"""
    import secrets

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
        # 文件存在但里面没有有效行 → 补一个
    token = secrets.token_urlsafe(24)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# 每行一个 token，# 开头为注释；首行为主 token\n")
        f.write("# 轮换时把新 token 写在最上面，旧 token 留一行，等客户端换完再删\n")
        f.write(token + "\n")
    log("已生成随机 token → %s" % os.path.basename(path))
    return token


# ======================================================================
# 三、后台运行器：在独立线程里跑 asyncio 事件循环
# ======================================================================
class Runner:
    """把 Frps / Frpc 的常驻协程放到后台线程跑，支持安全启停。"""

    def __init__(self):
        self.thread: "threading.Thread | None" = None
        self.loop: "asyncio.AbstractEventLoop | None" = None
        self.task = None
        self._ready = threading.Event()

    @property
    def running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def start(self, coro_factory, on_stopped=None) -> None:
        """coro_factory() 要返回一个协程；在新线程的事件循环里跑它。"""
        if self.running:
            return
        self._ready.clear()

        def _thread_main():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.loop = loop
            try:
                self.task = loop.create_task(coro_factory())
                self._ready.set()
                loop.run_until_complete(self.task)
            except asyncio.CancelledError:
                pass
            except Exception as exc:            # noqa: BLE001
                LOG.error("运行出错：%s", exc)
            finally:
                try:
                    pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                    for t in pending:
                        t.cancel()
                    if pending:
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True))
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:               # noqa: BLE001
                    pass
                finally:
                    loop.close()
                    self.loop = None
                    self.thread = None
                    if on_stopped:
                        on_stopped()

        self.thread = threading.Thread(target=_thread_main, daemon=True)
        self.thread.start()
        self._ready.wait(timeout=5)

    def stop(self, on_stopped=None) -> None:
        """请求停止：取消主协程，让后台线程自然收尾。"""
        if not self.running and self.loop is None:
            if on_stopped:
                on_stopped()
            return
        loop, task = self.loop, self.task
        if loop is not None and task is not None:
            loop.call_soon_threadsafe(task.cancel)
        if on_stopped:
            # 等线程真正结束再回调，避免"看起来停了其实还在"
            def _wait():
                t = self.thread
                if t is not None:
                    t.join(timeout=8)
                on_stopped()
            threading.Thread(target=_wait, daemon=True).start()


# ======================================================================
# 四、界面
# ======================================================================
def open_url(url: str) -> None:
    """用系统默认程序打开链接（浏览器 / 邮件客户端）。"""
    try:
        webbrowser.open(url)
    except Exception as exc:            # noqa: BLE001
        LOG.warning("无法打开链接 %s：%s", url, exc)


def make_link_label(parent, text: str, target: str, **kw) -> ttk.Label:
    """造一个"看起来像链接、点了会用浏览器打开"的标签。

    tkinter 没有内置超链接控件，这里用 Label + 手型光标 + 蓝色下划线模拟。
    """
    lbl = ttk.Label(parent, text=text, foreground="#1565c0",
                    cursor="hand2",
                    font=("Microsoft YaHei UI", 9, "underline"), **kw)
    lbl.bind("<Button-1>", lambda _e: open_url(target))
    return lbl


def build_about_dialog(parent: tk.Misc, center_on: "tk.Misc | None" = None) -> tk.Toplevel:
    """构建「关于」窗口：作者信息里的链接**直接可点**。

    为什么不用 messagebox？
        messagebox 只能显示纯文本，链接点了不会打开浏览器；
        作者主页既然要放上去，就得是能点开的。

    做成模块级函数（而不是 App 的方法）是为了让 exe 的 `--about`
    也能复用同一份实现 —— 两边各写一份迟早会不一致。
    """
    win = tk.Toplevel(parent)
    win.title("关于")
    if center_on is not None:
        win.transient(center_on)         # 跟随主窗口
    win.resizable(False, False)

    wrap = ttk.Frame(win, padding=18)
    wrap.pack(fill="both", expand=True)

    ttk.Label(wrap, text=about.APP_NAME,
              font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w")
    ttk.Label(wrap, text="版本 %s" % about.APP_VERSION,
              style="Hint.TLabel").pack(anchor="w", pady=(2, 10))
    ttk.Label(wrap, text=about.APP_DESCRIPTION,
              wraplength=360, justify="left").pack(anchor="w", pady=(0, 12))

    ttk.Separator(wrap, orient="horizontal").pack(fill="x", pady=(0, 12))
    ttk.Label(wrap, text="作者信息",
              font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w", pady=(0, 6))

    # 逐行：标签 + 可点值（邮箱走 mailto:，主页走 https:）
    info = [
        ("姓名", AUTHOR_NAME, None),
        ("邮箱", AUTHOR_EMAIL, "mailto:" + AUTHOR_EMAIL),
        ("主页", AUTHOR_HOMEPAGE, AUTHOR_HOMEPAGE),
    ]
    for label, value, target in info:
        row = ttk.Frame(wrap)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label + "：", width=6, anchor="e").pack(side="left")
        if target:
            make_link_label(row, value, target).pack(side="left")
        else:
            ttk.Label(row, text=value).pack(side="left")

    ttk.Label(wrap, text="点上方蓝色文字即可打开浏览器 / 邮件客户端",
              style="Hint.TLabel").pack(anchor="w", pady=(10, 0))
    ttk.Label(wrap, text=about.COPYRIGHT,
              style="Hint.TLabel").pack(anchor="w", pady=(10, 12))

    ttk.Button(wrap, text="关闭", command=win.destroy,
               width=12).pack(anchor="e")

    # 居中到主窗口
    win.update_idletasks()
    if center_on is not None:
        px, py = center_on.winfo_rootx(), center_on.winfo_rooty()
        pw, ph = center_on.winfo_width(), center_on.winfo_height()
    else:
        px = py = 200
        pw = ph = 800
    w, h = win.winfo_width(), win.winfo_height()
    win.geometry("+%d+%d" % (px + (pw - w) // 2, py + (ph - h) // 3))
    win.focus_set()
    return win


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        # ★ 高度必须 ≥ 内容的"自然高度"，否则 Tk 的 pack 会压缩最后打包的控件。
        #   实测：内容自然高度 709px，原先给 700px 时页脚每个标签被压掉 3px，
        #   "jsdczd" 里 j 的下伸部分正好被切掉 → 看起来像少了个字母。
        #   现在给足余量；页脚也改成了 side="bottom" 优先占位，
        #   所以这里的最小高度可以放宽，用户想缩窗口也不会切到署名。
        self.geometry("760x730")
        self.minsize(700, 620)

        # 日志队列 + 定时取用
        self.log_queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
        install_gui_logging(self.log_queue)

        self.server_runner = Runner()
        self.client_runner = Runner()

        self._build_style()
        self._build_widgets()
        self._poll_logs()

        LOG.info("%s 已就绪。数据目录：%s", APP_TITLE, DATA_DIR)
        LOG.info("作者：%s  |  %s  |  %s",
                 AUTHOR_NAME, AUTHOR_EMAIL, AUTHOR_HOMEPAGE)

    # ---------------- 样式 ----------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")        # Windows 原生观感
        except tk.TclError:
            pass
        style.configure("Hint.TLabel", foreground="#666666")
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 11, "bold"))
        style.configure("Run.TButton", font=("Microsoft YaHei UI", 9, "bold"))

    # ---------------- 布局 ----------------
    def _build_widgets(self):
        self._build_menubar()

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=(10, 0))

        self.server_tab = ttk.Frame(nb)
        self.client_tab = ttk.Frame(nb)
        nb.add(self.server_tab, text="  服务端（公网机器）  ")
        nb.add(self.client_tab, text="  客户端（内网机器）  ")

        self._build_server_tab(self.server_tab)
        self._build_client_tab(self.client_tab)

        # ★ 页脚（作者署名）在这里就打包，而且用 side="bottom"。
        #   为什么提前？
        #     Tk 的 pack 按"打包顺序"分配空间，空间不够时**最后打包的控件先被压缩**。
        #     原来页脚放在最末尾打包，于是窗口一不够高，它就被压掉几像素 ——
        #     表现是 "jsdczd" 里 j 的下伸被切掉（实测正是少 3px）。
        #     现在让页脚先"占住"底部，剩下的空间再给上面的日志区，
        #     这样无论窗口多小，署名都完整可见。
        self._build_footer()

        # 底部：状态 + 日志
        bottom = ttk.Frame(self)
        bottom.pack(side="top", fill="both", expand=True, padx=10, pady=(10, 6))

        bar = ttk.Frame(bottom)
        bar.pack(fill="x")
        self.server_status = ttk.Label(bar, text="服务端：未运行", foreground="#888888")
        self.server_status.pack(side="left")
        self.client_status = ttk.Label(bar, text="客户端：未运行", foreground="#888888")
        self.client_status.pack(side="left", padx=(16, 0))
        ttk.Button(bar, text="清空日志", command=self._clear_log).pack(side="right")

        log_frame = ttk.LabelFrame(bottom, text="运行日志")
        log_frame.pack(fill="both", expand=True, pady=(6, 0))
        self.log_text = tk.Text(log_frame, height=12, wrap="none",
                                bg="#1e1e1e", fg="#dcdcdc",
                                insertbackground="#dcdcdc",
                                font=("Consolas", 9), state="disabled")
        yscroll = ttk.Scrollbar(log_frame, orient="vertical",
                                command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)
        self.log_text.tag_config("ERROR", foreground="#ff6b6b")
        self.log_text.tag_config("WARNING", foreground="#ffd166")
        self.log_text.tag_config("INFO", foreground="#dcdcdc")
        self.log_text.tag_config("DEBUG", foreground="#8a8a8a")

    # ---- 菜单栏（「关于」入口）----
    def _build_menubar(self):
        menubar = tk.Menu(self)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于 / 作者信息", command=self._show_about)
        help_menu.add_separator()
        help_menu.add_command(label="访问作者主页",
                              command=lambda: self._open_url(AUTHOR_HOMEPAGE))
        help_menu.add_command(label="发送邮件给作者",
                              command=lambda: self._open_url("mailto:" + AUTHOR_EMAIL))
        menubar.add_cascade(label="帮助(H)", menu=help_menu)

        self.configure(menu=menubar)

    # ---- 页脚：作者信息（常驻可见，可点击）----
    def _build_footer(self):
        """底部一条作者署名栏。

        为什么要常驻而不是只放在「关于」里？
            署名是作者对这份作品的基本声明；常驻一行成本极低，
            而且链接可点 —— 想反馈问题或看更新时不用去翻文档。

        布局要点（实测踩过的坑）：
            · 用 side="bottom" 打包：让它优先占住窗口底部，
              空间不足时被压缩的会是上面的日志区，而不是署名本身。
            · 上下各留 8px 内边距：既是视觉呼吸，也保证字母的下伸
              （如 "jsdczd" 的 j）不会被文字行高裁掉。
        """
        footer = ttk.Frame(self)
        footer.pack(side="bottom", fill="x", padx=12, pady=(8, 8))

        ttk.Label(footer, text="作者：", style="Hint.TLabel").pack(side="left")
        # ipady=1：给文字行多一点垂直空间，避免下伸字母贴边
        ttk.Label(footer, text=AUTHOR_NAME, padding=(0, 1)).pack(side="left")

        ttk.Label(footer, text="  ·  ", style="Hint.TLabel").pack(side="left")
        self._link_label(footer, AUTHOR_HOMEPAGE, AUTHOR_HOMEPAGE).pack(side="left")

        ttk.Label(footer, text="  ·  ", style="Hint.TLabel").pack(side="left")
        self._link_label(footer, AUTHOR_EMAIL, "mailto:" + AUTHOR_EMAIL).pack(side="left")

        ttk.Label(footer, text="   (点击打开)", style="Hint.TLabel").pack(side="left")

    def _link_label(self, parent, text: str, target: str) -> ttk.Label:
        """可点链接标签（实现见模块级 make_link_label）。"""
        return make_link_label(parent, text, target)

    @staticmethod
    def _open_url(url: str) -> None:
        """用系统默认程序打开链接（实现见模块级 open_url）。"""
        open_url(url)

    # ---- 「关于」对话框 ----
    def _show_about(self):
        build_about_dialog(self, self)

    # ---- 服务端页 ----
    def _build_server_tab(self, parent):
        pad = {"padx": 8, "pady": 5}

        ttk.Label(parent, text="在这台公网机器上开监听，等待内网客户端接入",
                  style="Hint.TLabel").grid(row=0, column=0, columnspan=3,
                                            sticky="w", **pad)

        self.sv_port = tk.StringVar(value="8800")
        self.sv_user_host = tk.StringVar(value="0.0.0.0")
        self.sv_level = tk.StringVar(value="INFO")

        rows = [
            ("控制端口", self.sv_port, "供内网客户端连接（默认 8800）"),
            ("对外监听地址", self.sv_user_host, "一般留 0.0.0.0 表示所有网卡"),
            ("日志级别", self.sv_level, "DEBUG / INFO / WARNING / ERROR"),
        ]
        for i, (label, var, hint) in enumerate(rows, start=1):
            ttk.Label(parent, text=label, width=12, anchor="e").grid(
                row=i, column=0, sticky="e", **pad)
            ttk.Entry(parent, textvariable=var, width=24).grid(
                row=i, column=1, sticky="w", **pad)
            ttk.Label(parent, text=hint, style="Hint.TLabel").grid(
                row=i, column=2, sticky="w", **pad)

        btns = ttk.Frame(parent)
        btns.grid(row=10, column=0, columnspan=3, sticky="w", padx=8, pady=(14, 4))
        self.sv_btn = ttk.Button(btns, text="启动服务端", style="Run.TButton",
                                 command=self._toggle_server, width=16)
        self.sv_btn.pack(side="left")
        ttk.Button(btns, text="导出连接包（给客户端）",
                   command=self._export_pack).pack(side="left", padx=10)

        ttk.Label(
            parent,
            text=("说明：首次启动会自动生成自签证书与随机 token。\n"
                  "启动后点「导出连接包」，把生成的压缩包拷到内网机器上，\n"
                  "客户端页选择该包即可自动填好地址与凭据。"),
            style="Hint.TLabel", justify="left",
        ).grid(row=11, column=0, columnspan=3, sticky="w", padx=8, pady=(8, 4))

    # ---- 客户端页 ----
    def _build_client_tab(self, parent):
        pad = {"padx": 8, "pady": 5}

        ttk.Label(parent, text="把本机（内网）的服务，通过公网服务器暴露出去",
                  style="Hint.TLabel").grid(row=0, column=0, columnspan=3,
                                            sticky="w", **pad)

        self.cl_host = tk.StringVar()
        self.cl_port = tk.StringVar(value="8800")
        self.cl_local_host = tk.StringVar(value="127.0.0.1")
        self.cl_local_port = tk.StringVar(value="3389")
        self.cl_remote_port = tk.StringVar(value="9001")
        self.cl_name = tk.StringVar(value="myapp")
        self.cl_udp = tk.StringVar(value="")     # 留空 = 不启用 UDP
        self.cl_level = tk.StringVar(value="INFO")

        rows = [
            ("服务器地址", self.cl_host, "公网服务端的 IP 或域名（必填）"),
            ("服务器端口", self.cl_port, "与服务端「控制端口」一致"),
            ("本机服务地址", self.cl_local_host, "被穿透的服务所在地址"),
            ("本机服务端口", self.cl_local_port, "例：RDP=3389  Web=8080"),
            ("对外端口", self.cl_remote_port, "外部访问时用的端口，如 9001"),
            ("客户端名字", self.cl_name, "多客户端时须唯一，建议用用途命名"),
            ("UDP 对外端口", self.cl_udp, "可选，填了才转发 UDP（如 RDP-UDP）"),
            ("日志级别", self.cl_level, "DEBUG / INFO / WARNING / ERROR"),
        ]
        for i, (label, var, hint) in enumerate(rows, start=1):
            ttk.Label(parent, text=label, width=12, anchor="e").grid(
                row=i, column=0, sticky="e", **pad)
            ttk.Entry(parent, textvariable=var, width=24).grid(
                row=i, column=1, sticky="w", **pad)
            ttk.Label(parent, text=hint, style="Hint.TLabel").grid(
                row=i, column=2, sticky="w", **pad)

        btns = ttk.Frame(parent)
        btns.grid(row=20, column=0, columnspan=3, sticky="w", padx=8, pady=(14, 4))
        self.cl_btn = ttk.Button(btns, text="启动客户端", style="Run.TButton",
                                 command=self._toggle_client, width=16)
        self.cl_btn.pack(side="left")
        ttk.Button(btns, text="导入连接包",
                   command=self._import_pack).pack(side="left", padx=10)

        ttk.Label(
            parent,
            text=("说明：先填「服务器地址」，再点「导入连接包」选择服务端导出的包，\n"
                  "会自动带入正确的 CA 证书与 token。填好本机服务端口后即可启动。"),
            style="Hint.TLabel", justify="left",
        ).grid(row=21, column=0, columnspan=3, sticky="w", padx=8, pady=(8, 4))

    # ---------------- 日志 ----------------
    def _poll_logs(self):
        try:
            while True:
                level, text = self.log_queue.get_nowait()
                self._append_log(level, text)
        except queue.Empty:
            pass
        self.after(120, self._poll_logs)

    def _append_log(self, level: str, text: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", level if level in
                             ("ERROR", "WARNING", "INFO", "DEBUG") else "INFO")
        # 限制缓冲行数，避免长时间运行吃光内存
        if int(self.log_text.index("end-1c").split(".")[0]) > 2000:
            self.log_text.delete("1.0", "200.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # ---------------- 服务端启停 ----------------
    def _toggle_server(self):
        if self.server_runner.running:
            LOG.info("正在停止服务端……")
            self.sv_btn.configure(state="disabled")
            self.server_runner.stop(on_stopped=self._server_stopped)
        else:
            self._start_server()

    def _start_server(self):
        port = self._parse_port(self.sv_port.get(), "控制端口")
        if port is None:
            return
        host = self.sv_user_host.get().strip() or "0.0.0.0"
        level = self.sv_level.get().strip().upper() or "INFO"

        # 首次运行自动准备证书与 token
        if not ensure_certs("localhost", CERT_DIR, log=LOG.info):
            messagebox.showerror("证书生成失败",
                                 "无法生成自签证书，请确认已安装 cryptography。\n"
                                 "（打包版已内置，源码运行需 pip install cryptography）")
            return
        ensure_token(TOKEN_FILE, log=LOG.info)

        args = _Namespace(
            serve_host="0.0.0.0", serve_port=port, user_host=host,
            token="", token_file=TOKEN_FILE,
            cert_file=os.path.join(CERT_DIR, "server.crt"),
            key_file=os.path.join(CERT_DIR, "server.key"),
            ca_cert_file=os.path.join(CERT_DIR, "ca.crt"),
            ca_key_file=os.path.join(CERT_DIR, "ca.key"),
            cert_host=[], cert_renew_days=30,
            max_conn_per_ip=20, max_active_conns=100, max_queued=50,
            udp_target_addr="", max_udp_sessions=512, udp_session_timeout=60,
            enable_p2p=True,
            log_level=level,
        )
        _set_level(level)
        LOG.info("启动服务端：监听 0.0.0.0:%d", port)
        self.server_runner.start(lambda: _run_server(args),
                                 on_stopped=self._server_stopped)
        self.sv_btn.configure(text="停止服务端")
        self.server_status.configure(text="服务端：运行中", foreground="#2e7d32")

    def _server_stopped(self):
        self.sv_btn.configure(text="启动服务端", state="normal")
        self.server_status.configure(text="服务端：未运行", foreground="#888888")
        LOG.info("服务端已停止")

    # ---------------- 客户端启停 ----------------
    def _toggle_client(self):
        if self.client_runner.running:
            LOG.info("正在停止客户端……")
            self.cl_btn.configure(state="disabled")
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

        if not ensure_certs(host, CERT_DIR, log=LOG.info):
            messagebox.showerror("证书生成失败", "无法生成自签证书。")
            return
        ensure_token(TOKEN_FILE, log=LOG.info)

        args = _Namespace(
            serve_host=host, serve_port=port,
            local_host=self.cl_local_host.get().strip() or "127.0.0.1",
            local_port=local_port,
            proxy_name=self.cl_name.get().strip() or "myapp",
            remote_port=remote_port,
            udp_port=udp_port, udp_local_port=udp_port or 0,
            p2p_timeout=3.0, enable_p2p=True,
            token="", token_file=TOKEN_FILE,
            ca_file=os.path.join(CERT_DIR, "ca.crt"),
            insecure=False, no_tls=False,
            log_level=self.cl_level.get().strip().upper() or "INFO",
        )
        _set_level(args.log_level)
        LOG.info("启动客户端：%s:%d  →  本机 %s:%d  （对外端口 %d%s）",
                 host, port, args.local_host, local_port, remote_port,
                 "，UDP %d" % udp_port if udp_port else "")
        self.client_runner.start(lambda: _run_client(args),
                                 on_stopped=self._client_stopped)
        self.cl_btn.configure(text="停止客户端")
        self.client_status.configure(text="客户端：运行中", foreground="#2e7d32")

    def _client_stopped(self):
        self.cl_btn.configure(text="启动客户端", state="normal")
        self.client_status.configure(text="客户端：未运行", foreground="#888888")
        LOG.info("客户端已停止")

    # ---------------- 工具 ----------------
    def _parse_port(self, text: str, label: str):
        text = (text or "").strip()
        if not text.isdigit() or not (1 <= int(text) <= 65535):
            messagebox.showwarning("端口不合法",
                                   "%s 需要 1-65535 之间的整数，当前为：%r"
                                   % (label, text))
            return None
        return int(text)

    # ---------------- 连接包导出 / 导入 ----------------
    def _export_pack(self):
        """把客户端需要的两样东西打成一个 zip：ca.crt + tokens.txt。"""
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
        messagebox.showinfo("导出成功",
                            "连接包已保存：\n%s\n\n请将它拷贝到内网机器的客户端里导入。" % path)

    def _import_pack(self):
        """从连接包导入 ca.crt 与 token（客户端用）。"""
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
        messagebox.showinfo("导入成功",
                            "已导入 CA 证书与 token。\n"
                            "接下来填写「本机服务端口」与「对外端口」即可启动。")


# ======================================================================
# 五、辅助：轻量 args 容器 + 运行封装
# ======================================================================
class _Namespace:
    """一个能用属性访问的简单命名空间（替代 argparse.Namespace）。"""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def _set_level(level: str) -> None:
    lv = parse_log_level(level)
    for name in ("frps", "frpc"):
        logging.getLogger(name).setLevel(lv)


async def _run_server(args) -> None:
    import frps
    await frps.Frps(args).start()


async def _run_client(args) -> None:
    import frpc
    await frpc.Frpc(args).start()


# ======================================================================
# 六、隐藏自检模式（--selftest）
# ======================================================================
# 用途：exe 是图形程序，不方便自动化验证"里面的网络逻辑是否完好"。
#       加上这个开关后，可以在命令行里跑一次真实的内网穿透，
#       全程不弹窗口，几秒内出结果 —— 既方便打包后回归，也方便用户自查。
async def _selftest() -> int:
    import frps
    import frpc

    tmp = os.path.join(os.environ.get("TEMP", os.path.dirname(DATA_DIR)),
                       "frp_selftest_%d" % os.getpid())
    os.makedirs(tmp, exist_ok=True)
    cert_dir = os.path.join(tmp, "certs")

    if not ensure_certs("localhost", cert_dir, log=LOG.info):
        return 2
    tk_path = os.path.join(tmp, "tokens.txt")
    ensure_token(tk_path, log=LOG.info)

    # 1) 起一个"内网服务"，用来验证穿透真的通了
    echoed = []

    async def _echo(reader, writer):
        try:
            data = await reader.read(64)
            echoed.append(data)
            writer.write(b"ECHO:" + data)
            await writer.drain()
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    local_srv = await asyncio.start_server(_echo, "127.0.0.1", 19991)

    # 2) 启服务端
    sargs = _Namespace(
        serve_host="127.0.0.1", serve_port=19880, user_host="127.0.0.1",
        token="", token_file=tk_path,
        cert_file=os.path.join(cert_dir, "server.crt"),
        key_file=os.path.join(cert_dir, "server.key"),
        ca_cert_file=os.path.join(cert_dir, "ca.crt"),
        ca_key_file=os.path.join(cert_dir, "ca.key"),
        cert_host=["localhost"], cert_renew_days=30,
        max_conn_per_ip=20, max_active_conns=100, max_queued=50,
        udp_target_addr="", max_udp_sessions=512, udp_session_timeout=60,
        enable_p2p=False, log_level="ERROR",
    )
    server = frps.Frps(sargs)
    server_task = asyncio.create_task(server.start())

    # 3) 启客户端
    cargs = _Namespace(
        serve_host="localhost", serve_port=19880,
        local_host="127.0.0.1", local_port=19991,
        proxy_name="selftest", remote_port=19001,
        udp_port=0, udp_local_port=0, p2p_timeout=3.0, enable_p2p=False,
        token="", token_file=tk_path,
        ca_file=os.path.join(cert_dir, "ca.crt"),
        insecure=False, no_tls=False, log_level="ERROR",
    )
    client = frpc.Frpc(cargs)
    client_task = asyncio.create_task(client.start())

    ok = False
    try:
        # 等服务端注册上（最多 15 秒）
        for _ in range(150):
            if server.sessions:
                break
            await asyncio.sleep(0.1)

        if not server.sessions:
            LOG.error("自检失败：客户端未能接入服务端")
        else:
            # 从外部访问对外端口，验证数据真的穿透到内网服务。
            # ★ 用户端口是带 TLS 的（服务端统一用 ssl_ctx 监听），
            #   所以这里必须用 CA 建 SSLContext —— 否则握手失败，
            #   表现是"连接建立了但收不到任何数据"，很容易误判成转发坏了。
            import ssl as _ssl
            ctx = _ssl.create_default_context(
                cafile=os.path.join(cert_dir, "ca.crt"))
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", 19001, ssl=ctx)
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
    except Exception as exc:            # noqa: BLE001
        LOG.error("自检异常：%s", exc)
    finally:
        client_task.cancel()
        server_task.cancel()
        await asyncio.gather(client_task, server_task, return_exceptions=True)
        local_srv.close()
        try:
            await asyncio.wait_for(local_srv.wait_closed(), timeout=1.0)
        except Exception:
            pass
        import shutil as _sh
        _sh.rmtree(tmp, ignore_errors=True)

    if ok:
        print("SELFTEST: PASS")
        return 0
    print("SELFTEST: FAIL")
    return 1


def main() -> int:
    # 隐藏自检：exe --selftest
    if "--selftest" in sys.argv:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%H:%M:%S")
        return asyncio.run(_selftest())

    # 只看作者信息：exe --about
    # ★ 为什么不做成"打印到控制台"？
    #   打包用的是 --noconsole（窗口子系统），exe 根本没有标准输出，
    #   print 出去什么也看不到。所以这里直接把「关于」窗口弹出来，
    #   源码运行和 exe 运行表现一致。若确实有控制台（源码模式），顺便也打印一份。
    if "--about" in sys.argv or "-v" in sys.argv or "--version" in sys.argv:
        if sys.stdout is not None:
            with contextlib.suppress(Exception):
                print(about.summary())
                for _k, _v in about.author_lines():
                    print("  %s：%s" % (_k, _v))
        return _show_about_window()

    app = App()

    def _on_close():
        if app.server_runner.running or app.client_runner.running:
            if not messagebox.askyesno("确认退出",
                                       "服务仍在运行，确定要退出吗？"):
                return
            app.server_runner.stop()
            app.client_runner.stop()
        app.destroy()

    app.protocol("WM_DELETE_WINDOW", _on_close)
    app.mainloop()
    return 0


def _show_about_window() -> int:
    """单独弹一个「关于」窗口（不启动主界面），用于 exe --about。

    为什么要专门做这个？
        打包用的是 --noconsole（窗口子系统），exe 没有标准输出，
        print 出去什么也看不到。所以 --about 必须弹窗才看得见，
        而且源码运行与 exe 运行表现一致。
    """
    root = tk.Tk()
    root.withdraw()                     # 只用一个隐藏的根窗口承载对话框

    style = ttk.Style(root)
    with contextlib.suppress(tk.TclError):
        style.theme_use("vista")
    style.configure("Hint.TLabel", foreground="#666666")

    win = build_about_dialog(root, center_on=None)
    # 关掉「关于」即退出程序（否则隐藏的 root 会让进程悬着）
    win.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
