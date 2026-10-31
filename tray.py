"""
tray.py —— 系统托盘常驻（最小化到通知区域）

为什么需要它？
    内网穿透是"挂在那儿一直跑"的东西，用户不会一直开着窗口。
    关掉窗口就得重开、重连，很别扭；更常见的是"点错关闭把服务关了"。
    所以需要一个托盘图标：最小化后缩到右下角，双击唤回，右键退出。

为什么不装 pystray？
    本机 pip 连不上 PyPI（隧道 502），而且要让 exe 保持单文件零依赖。
    这里直接用 ctypes 调 Win32 的 Shell_NotifyIcon —— 只用系统 DLL，没有额外包袱。

实现要点（都是 Win32 的老规矩，缺一不可）：
    1. 托盘图标需要一个**窗口**来收消息，所以先注册窗口类再建一个隐藏窗口；
    2. 消息循环必须跑在**独立的线程**里 —— Tk 的主循环在另一条线程，
       两边的消息不能混在一起处理；
    3. 托盘回调发生在托盘线程，而界面只能由主线程改，
       所以回调统一用 `marshal`（通常是 root.after）丢回主线程执行；
    4. 退出时要 NIM_DELETE，否则图标会变成"幽灵"残留到鼠标划过才消失。
"""

import ctypes
import ctypes.wintypes as wt
import contextlib
import logging
import os
import sys
import threading
import time

logger = logging.getLogger("tray")
# 只做"保底可见"：如果没有任何 handler（比如单跑 tray.py），
# 日志会落到 lastResort（只显示 WARNING+），INFO 会被静默丢掉。
# 注意 **不要** 在这里挂 StreamHandler 也不要设 propagate=False ——
# 真正的输出 handler 由 protocol.install_logging() 统一挂到本 logger 上
# （见 protocol.NAMED_LOGGERS），这样界面日志窗口与 7 天日志文件都能收到。
if not logger.handlers:
    logger.addHandler(logging.NullHandler())
logger.setLevel(logging.DEBUG)

# ---------------------------------------------------------------- Win32 常量
WM_APP = 0x8000
WM_TRAYICON = WM_APP + 1
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_DESTROY = 0x0002
WM_COMMAND = 0x0111
WM_QUIT = 0x0012

NIM_ADD, NIM_MODIFY, NIM_DELETE, NIM_SETVERSION = 0, 1, 2, 4
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x01, 0x02, 0x04, 0x10
NOTIFYICON_VERSION_4 = 4

IMAGE_ICON = 1
LR_LOADFROMFILE, LR_DEFAULTSIZE = 0x0010, 0x0040

MF_STRING, MF_SEPARATOR = 0x0000, 0x0800
TPM_RIGHTBUTTON, TPM_RETURNCMD = 0x0002, 0x0100

IDM_SHOW, IDM_HIDE, IDM_EXIT = 1001, 1002, 1003

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_byte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("hWnd", wt.HWND),
        ("uID", wt.UINT),
        ("uFlags", wt.UINT),
        ("uCallbackMessage", wt.UINT),
        ("hIcon", wt.HICON),
        ("szTip", ctypes.c_wchar * 128),
        ("dwState", wt.DWORD),
        ("dwStateMask", wt.DWORD),
        ("szInfo", ctypes.c_wchar * 256),
        ("uVersion", wt.UINT),
        ("szInfoTitle", ctypes.c_wchar * 64),
        ("dwInfoFlags", wt.DWORD),
        ("guidItem", GUID),
        ("hBalloonIcon", wt.HICON),
    ]


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.UINT), ("style", wt.UINT), ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
        ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON),
        ("hCursor", wt.HANDLE), ("hbrBackground", wt.HBRUSH),
        ("lpszMenuName", wt.LPCWSTR), ("lpszClassName", wt.LPCWSTR),
        ("hIconSm", wt.HICON),
    ]


class TrayIcon:
    """通知区域图标 + 右键菜单。

    参数：
        icon_path — .ico 文件路径
        tooltip   — 悬停提示文字
        on_show   — 双击/菜单「显示主界面」时调用（在**主线程**执行）
        on_exit   — 菜单「退出」时调用（在主线程执行）
        marshal   — 把回调丢回主线程的函数，通常是 root.after
    """

    CLASS_NAME = "FrpTunnelTrayWnd"

    def __init__(self, icon_path: str, tooltip: str = "内网穿透助手",
                 on_show=None, on_exit=None, marshal=None,
                 on_toggle: "callable | None" = None):
        self.icon_path = icon_path
        self.tooltip = tooltip
        self.on_show = on_show
        self.on_exit = on_exit
        self.on_toggle = on_toggle
        self._marshal = marshal or (lambda fn: fn())

        self._hwnd = None
        self._thread = None
        self._thread_id = 0
        self._ready = threading.Event()
        self._visible = False
        self._wndproc_ref = None      # 必须留引用，否则回调被 GC 后崩溃
        self._hicon = None
        self._nid = None
        self.last_result = None       # 最近一次 Shell_NotifyIcon 的结果（排障用）
        self._promote_done = False    # 本次运行是否已处理过"图标常显"

    # ---------------------------------------------------------------- 对外接口
    @property
    def available(self) -> bool:
        return self._hwnd is not None

    @property
    def visible(self) -> bool:
        return self._visible

    def start(self) -> bool:
        """启动托盘线程；成功返回 True。"""
        if self._thread is not None and self._thread.is_alive():
            return True
        self._thread = threading.Thread(target=self._run, name="tray",
                                        daemon=True)
        self._thread.start()
        self._ready.wait(3.0)
        return self._hwnd is not None

    def stop(self) -> None:
        """移除图标并结束托盘线程。"""
        self._remove_icon()
        if self._thread_id:
            try:
                ctypes.windll.user32.PostThreadMessageW(self._thread_id,
                                                        WM_QUIT, 0, 0)
            except OSError:
                pass
        self._thread = None
        self._hwnd = None

    def show_icon(self) -> None:
        self._visible = True
        self._post("add")

    def hide_icon(self) -> None:
        self._visible = False
        self._post("del")

    def set_tooltip(self, text: str) -> None:
        self.tooltip = text
        self._post("tip")

    def notify(self, title: str, text: str) -> None:
        """弹一个气泡提示（不点也不影响）。"""
        self._post("info", (title, text))

    # ---------------------------------------------------------------- 内部
    def _post(self, action: str, payload=None) -> None:
        """给托盘线程发个自定义消息，让它去改图标状态。

        为什么要绕一圈？所有 Shell_NotifyIcon 调用都应该在**创建图标的
        那条线程**里做，跨线程直接调虽然多数时候没事，但不保证。
        """
        if not self._hwnd:
            return
        # 把参数保存下来，让托盘线程去取（避免再分配跨线程内存）
        self._pending = (action, payload)
        try:
            ctypes.windll.user32.PostMessageW(self._hwnd, WM_TRAYICON + 100, 0, 0)
        except OSError:
            pass

    # ---------------------------------------------------------------- 线程主体
    def _run(self) -> None:
        self._thread_id = ctypes.windll.kernel32.GetCurrentThreadId()
        u = ctypes.windll.user32
        k = ctypes.windll.kernel32
        shell32 = ctypes.windll.shell32

        # ★ 必须显式声明参数类型。
        #   不声明的话 ctypes 默认按 C int（32 位）传参，而窗口消息的
        #   LPARAM/WPARAM 在 64 位下是 64 位 —— 只要值大一点就会抛
        #   "OverflowError: int too long to convert"，而且异常发生在
        #   回调函数里，只会被打印成 "Exception ignored"，很难定位。
        u.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
        u.DefWindowProcW.restype = LRESULT
        u.CreateWindowExW.restype = wt.HWND
        u.CreateWindowExW.argtypes = [
            wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID]
        u.LoadImageW.restype = wt.HANDLE
        u.LoadImageW.argtypes = [wt.HINSTANCE, wt.LPCWSTR, wt.UINT,
                                 ctypes.c_int, ctypes.c_int, wt.UINT]
        u.CreatePopupMenu.restype = wt.HMENU
        u.TrackPopupMenu.restype = ctypes.c_int
        u.TrackPopupMenu.argtypes = [wt.HMENU, wt.UINT, ctypes.c_int,
                                     ctypes.c_int, ctypes.c_int, wt.HWND,
                                     ctypes.c_void_p]
        shell32.Shell_NotifyIconW.argtypes = [wt.DWORD, ctypes.c_void_p]
        shell32.Shell_NotifyIconW.restype = wt.BOOL

        hinst = k.GetModuleHandleW(None)

        def wndproc(hwnd, msg, wparam, lparam):
            if msg == WM_TRAYICON:
                self._on_tray_message(wparam, lparam)
                return 0
            if msg == WM_TRAYICON + 100:
                self._apply_pending()
                return 0
            if msg == WM_DESTROY:
                u.PostQuitMessage(0)
                return 0
            return u.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc_ref = WNDPROC(wndproc)

        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinst
        wc.lpszClassName = self.CLASS_NAME
        if not u.RegisterClassExW(ctypes.byref(wc)):
            logger.warning("托盘：注册窗口类失败（可能已存在），继续尝试用已有类")

        hwnd = u.CreateWindowExW(0, self.CLASS_NAME, "frp-tray", 0,
                                 0, 0, 0, 0, None, None, hinst, None)
        if not hwnd:
            logger.warning("托盘：创建隐藏窗口失败，托盘功能不可用")
            self._ready.set()
            return
        self._hwnd = hwnd

        # 载入图标
        try:
            self._hicon = u.LoadImageW(None, self.icon_path, IMAGE_ICON, 0, 0,
                                       LR_LOADFROMFILE | LR_DEFAULTSIZE)
        except OSError:
            self._hicon = None
        if not self._hicon:
            # 退而求其次：用系统的"应用程序"图标，至少能显示出个东西
            self._hicon = u.LoadIconW(None, wt.LPCWSTR(32512))
            logger.warning("托盘：无法载入 %s，改用系统默认图标", self.icon_path)

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = self._hicon
        nid.szTip = self.tooltip[:127]
        self._nid = nid

        self._ready.set()               # 先放行 start()，再进消息循环

        msg = wt.MSG()
        while True:
            ret = u.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if ret in (0, -1):          # WM_QUIT 或出错
                break
            u.TranslateMessage(ctypes.byref(msg))
            u.DispatchMessageW(ctypes.byref(msg))

        # 收尾：一定要把图标摘掉
        try:
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
        except OSError:
            pass
        self._hwnd = None

    def _apply_pending(self) -> None:
        """在托盘线程里真正执行 Shell_NotifyIcon。"""
        action, payload = getattr(self, "_pending", (None, None))
        shell32 = ctypes.windll.shell32
        if not self._nid:
            return
        try:
            if action == "add":
                ok = shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self._nid))
                self.last_result = ("add", bool(ok))
                if ok:
                    logger.info("托盘图标已添加到通知区域")
                    # Win11 默认把新图标塞进"^"折叠区 —— 对"最小化到托盘"
                    # 的用法来说等于"程序消失了"，用户找不到图标也找不回窗口。
                    # 后台线程把自己设为常显（不阻塞托盘线程的消息循环）。
                    if not self._promote_done:
                        threading.Thread(target=self._promote_icon,
                                         name="tray-promote",
                                         daemon=True).start()
                else:
                    # 失败时窗口已经 withdraw 了，图标又不出现 = 用户找不回窗口。
                    # 必须留下显著日志，否则这种事故完全静默。
                    logger.warning("托盘图标添加失败（NIM_ADD 返回 False），"
                                   "窗口已收进托盘但图标可能不可见")
                self._nid.uVersion = NOTIFYICON_VERSION_4
                shell32.Shell_NotifyIconW(NIM_SETVERSION, ctypes.byref(self._nid))
            elif action == "del":
                ok = shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
                self.last_result = ("del", bool(ok))
                if not ok:
                    logger.debug("托盘图标移除失败（可能本就没有）")
            elif action == "tip":
                self._nid.szTip = self.tooltip[:127]
                shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self._nid))
            elif action == "info":
                title, text = payload or ("", "")
                self._nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_INFO
                self._nid.szInfo = text[:255]
                self._nid.szInfoTitle = title[:63]
                self._nid.dwInfoFlags = 1        # NIIF_INFO
                shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self._nid))
                self._nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        except OSError as exc:
            self.last_result = (action, "异常: %s" % exc)
            logger.debug("托盘操作 %s 失败：%s", action, exc)

    # ------------------------------------------------------- 图标常显（Win11）
    def _promote_icon(self) -> None:
        """把托盘图标设为「常显」，不藏在 Win11 的 "^" 折叠区里。

        为什么需要：
            Win11 默认把所有新出现的托盘图标放进折叠区。对"最小化到托盘"
            的用法来说这等于"程序消失了"—— 用户既找不到图标，也找不回
            窗口，只能去 设置 → 个性化 → 任务栏 → 其他系统托盘图标 里翻。

        怎么做到的：
            微软没有公开 API 控制这个，唯一可用的开关是注册表：
                HKCU\\Control Panel\\NotifyIconSettings\\<项>\\IsPromoted = 1
            项名是 exe 路径的哈希（算法未公开），由 explorer 在图标首次
            出现时创建 —— 所以只能遍历所有项，找 ExecutablePath == 自己。

        ★ 实测（2026-10-14，Win11）：
            · 项在图标添加后约 0.3 秒就会由 explorer 创建；
            · 写入 IsPromoted 立即生效 —— 不用重启 explorer、不用重加图标。

        尊重用户：
            只在 IsPromoted 从未被设置过时，补一个默认值 1。
            若用户手动关过（值 = 0），说明人家就是想要折叠，保持现状。
        """
        mine = set()
        # 源码运行时 venv 的 python.exe 可能是个"重定向器"，
        # explorer 记录的是真实进程（base python）的路径，两个都算候选。
        for exe in (getattr(sys, "executable", ""),
                    getattr(sys, "_base_executable", "")):
            if exe:
                with contextlib.suppress(OSError, ValueError):
                    mine.add(os.path.normcase(os.path.abspath(exe)))
        if not mine:
            return

        for _ in range(20):              # 最多等 10 秒（通常第一次就命中）
            try:
                state = self._promote_once(mine)
            except Exception as exc:     # noqa: BLE001  托盘辅助功能，绝不能抛
                logger.debug("托盘常显设置异常：%s", exc)
                return
            if state is True:
                self._promote_done = True
                return
            time.sleep(0.5)
        logger.debug("暂未找到自己的托盘设置项，图标仍在折叠区")

    @staticmethod
    def _promote_once(mine):
        """尝试一轮。True = 已处理完；False = 项还没出现（可稍后重试）。"""
        import winreg
        try:
            root = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                  r"Control Panel\NotifyIconSettings")
        except OSError:
            return False
        try:
            for i in range(winreg.QueryInfoKey(root)[0]):
                try:
                    sub = winreg.EnumKey(root, i)
                    k = winreg.OpenKey(root, sub)
                except OSError:
                    continue
                found = False
                try:
                    try:
                        ep = str(winreg.QueryValueEx(k, "ExecutablePath")[0] or "")
                    except OSError:
                        ep = ""
                    if os.path.normcase(ep) in mine:
                        found = True
                        try:
                            winreg.QueryValueEx(k, "IsPromoted")
                            # 值已存在：1=已是常显；0=用户手动关过。都保持现状。
                            return True
                        except FileNotFoundError:
                            pass             # 从未设过 → 下面补默认值
                        except OSError:
                            return False
                finally:
                    winreg.CloseKey(k)
                if found:
                    try:
                        wk = winreg.OpenKey(root, sub, 0, winreg.KEY_SET_VALUE)
                        try:
                            winreg.SetValueEx(wk, "IsPromoted", 0,
                                              winreg.REG_DWORD, 1)
                            logger.info("托盘图标已设为常显（不再藏在折叠区）")
                        finally:
                            winreg.CloseKey(wk)
                    except OSError as exc:
                        logger.debug("写入 IsPromoted 失败：%s", exc)
                    return True
            return False                     # 自己的项还没出现
        finally:
            winreg.CloseKey(root)

    def _on_tray_message(self, wparam, lparam) -> None:
        """托盘图标的鼠标事件。lparam 的低 16 位才是事件类型（v4 语义）。"""
        event = lparam & 0xFFFF if lparam > 0xFFFF else lparam
        if event in (WM_LBUTTONDBLCLK, WM_LBUTTONUP):
            if self.on_toggle is not None:
                self._marshal(self.on_toggle)
            elif self.on_show is not None:
                self._marshal(self.on_show)
        elif event == WM_RBUTTONUP:
            self._show_menu()

    def _show_menu(self) -> None:
        u = ctypes.windll.user32
        menu = u.CreatePopupMenu()
        if not menu:
            return
        try:
            u.AppendMenuW(menu, MF_STRING, IDM_SHOW, "显示主界面")
            u.AppendMenuW(menu, MF_SEPARATOR, 0, None)
            u.AppendMenuW(menu, MF_STRING, IDM_EXIT, "退出程序")

            # TrackPopupMenu 要求窗口在前台，否则菜单一闪就没
            pt = wt.POINT()
            u.GetCursorPos(ctypes.byref(pt))
            u.SetForegroundWindow(self._hwnd)
            cmd = u.TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD,
                                   pt.x, pt.y, 0, self._hwnd, None)
            u.PostMessageW(self._hwnd, 0x0000, 0, 0)     # WM_NULL，菜单收尾惯例
            if cmd == IDM_SHOW and self.on_show is not None:
                self._marshal(self.on_show)
            elif cmd == IDM_EXIT and self.on_exit is not None:
                self._marshal(self.on_exit)
        finally:
            u.DestroyMenu(menu)

    def _remove_icon(self) -> None:
        if not self._nid:
            return
        try:
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE,
                                                    ctypes.byref(self._nid))
        except OSError:
            pass
