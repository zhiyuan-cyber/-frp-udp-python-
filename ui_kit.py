"""
ui_kit.py —— 界面组件与配色

参考 Clash Verge 的浅色风格：浅灰蓝底 + 白色圆角卡片 + 蓝色主色，
左侧竖排导航、右侧分模块内容。

为什么自己画而不用现成主题库？
    本机 pip 连不上 PyPI（隧道 502），customtkinter 之类装不了；
    而且为了让 exe 保持"单文件、零额外依赖"，用 tkinter 的 Canvas
    自绘圆角与图表是最稳的路子 —— 效果也够用。

所有尺寸/颜色都集中在本模块顶部的常量里，改主题只动这一处。
"""

import ctypes
import tkinter as tk
from tkinter import font as tkfont

# ===========================================================================
# 配色（浅色主题）
# ===========================================================================
BG_PAGE = "#eef1f6"        # 页面底色（浅灰蓝）
BG_SIDEBAR = "#ffffff"     # 侧边栏
BG_CARD = "#ffffff"        # 卡片
BG_SOFT = "#f5f7fb"        # 卡片内的次级块
BG_HOVER = "#f2f5fa"       # 悬停
BG_ACTIVE = "#e8f0fe"      # 选中
BORDER = "#e4e9f0"         # 描边
BORDER_SOFT = "#eef2f7"

TEXT = "#1f2a37"           # 主文字
TEXT_SUB = "#5b6675"       # 次要文字
TEXT_MUTED = "#93a0b0"     # 弱化文字
TEXT_ON_ACCENT = "#ffffff"

ACCENT = "#2563eb"         # 主色（蓝）
ACCENT_DARK = "#1d4ed8"
ACCENT_SOFT = "#e8f0fe"

UP = "#f59e0b"             # 上传（橙）
UP_SOFT = "#fef3c7"
DOWN = "#2563eb"           # 下载（蓝）
DOWN_SOFT = "#dbeafe"

OK = "#16a34a"
OK_SOFT = "#dcfce7"
WARN = "#d97706"
WARN_SOFT = "#fef3c7"
ERR = "#dc2626"
ERR_SOFT = "#fee2e2"
INFO_SOFT = "#e0f2fe"

# ===========================================================================
# 尺寸（设计稿值，实际使用时经 dp() 按 DPI 换算）
# ===========================================================================
RADIUS = 12
PAD = 16
GAP = 12
SIDEBAR_W = 184

FONT_UI = "Microsoft YaHei UI"
FONT_MONO = "Consolas"

# ---------------------------------------------------------------------------
# DPI 适配
# ---------------------------------------------------------------------------
SCALE = 1.0


def enable_dpi_awareness() -> None:
    """让进程按显示器 DPI 渲染。

    ★ 为什么必须做？
        Windows 对"不声明 DPI 感知"的程序会做**位图拉伸**：
        程序按 96 DPI 画好画面，系统再整体放大到 125%/150%。
        文字因此发虚 —— 这是"字体模糊"最常见的成因。
        声明之后由程序自己按真实 DPI 渲染，字就实了。

    必须在**创建任何窗口之前**调用，否则不生效。
    """
    try:
        # PROCESS_PER_MONITOR_DPI_AWARE = 2（Win8.1+，支持多显示器不同缩放）
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except (AttributeError, OSError):
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()      # Vista/7 的老接口
    except (AttributeError, OSError):
        pass


def init_scaling(root: tk.Misc) -> float:
    """按真实 DPI 校准 Tk 的字号与我们的像素尺寸，返回缩放系数。

    · Tk 的字体尺寸单位是"点"，`tk scaling` 决定一点折多少像素；
      设成 dpi/72 后，字号会**自动**跟着显示器放大，不必自己乘。
    · 但 padx/pady/width 这些像素值 Tk 不管，所以要用 dp() 手动乘。
    """
    global SCALE
    try:
        dpi = float(root.winfo_fpixels("1i"))
    except (tk.TclError, ValueError):
        dpi = 96.0
    # 只放大不缩小：小 DPI 下把界面缩得更小没有意义
    SCALE = max(1.0, round(dpi / 96.0, 2))
    try:
        root.tk.call("tk", "scaling", dpi / 72.0)
    except tk.TclError:
        pass
    return SCALE


def dp(value: float) -> int:
    """设计稿像素 → 当前 DPI 下的像素。"""
    return int(round(value * SCALE))


# 侧边栏图标（都用 Geometric Shapes / Misc Symbols，实测本机各字体都能渲染）
ICONS = {
    "home": "\u2302",      # ⌂
    "server": "\u25A3",    # ▣
    "client": "\u25A4",    # ▤
    "rules": "\u26E8",     # ⛨ 盾牌，正好配"过滤规则"
    "log": "\u2261",       # ≡
    "about": "\u2699",     # ⚙
    "traffic": "\u223F",   # ∿
    "up": "\u2191",        # ↑
    "down": "\u2193",      # ↓
    "dot": "\u25CF",       # ●
    "ring": "\u25CB",      # ○
    "link": "\u21C4",      # ⇄
    "bolt": "\u26A1",      # ⚡
}


def ui_font(size=10, weight="normal"):
    return (FONT_UI, size, weight)


def mono_font(size=10, weight="normal"):
    return (FONT_MONO, size, weight)


# ===========================================================================
# 绘图小工具
# ===========================================================================
def round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw):
    """在 Canvas 上画一个圆角矩形。

    原理：用一条"带圆角控制点"的多边形 + smooth=True，让 Tk 自己用样条
    把角磨圆。比用 4 段 arc 拼简单得多，视觉上足够。
    （纯 tkinter 没有圆角控件，这是最省事且稳定的做法。）
    """
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]
    return canvas.create_polygon(pts, smooth=True, **kw)


def fit_text(text: str, limit: int) -> str:
    """太长就截断加省略号（Canvas 里没有自动省略）。"""
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ===========================================================================
# 圆角卡片
# ===========================================================================
class Card(tk.Canvas):
    """自动适应内容高度的白色圆角卡片。

    用法：
        card = Card(parent, title="流量统计")
        card.pack(fill="x", pady=...)
        ... 往 card.body 里塞控件 ...

    实现要点：
        卡片本体是一个 Canvas（负责画圆角背景），内容放一个 Frame，
        用 create_window 挂到 Canvas 上。内容 Frame 尺寸一变，
        就把 Canvas 的高度调成"内容高 + 上下留白"，从而实现自适应高度。
    """

    def __init__(self, parent, title: str = "", icon: str = "",
                 pad: int = PAD, radius: int = RADIUS,
                 bg: str = BG_CARD, outer: str = BG_PAGE,
                 min_height: int = 0, **kw):
        # 设计稿像素 → 实际像素（DPI 适配）
        pad = dp(pad)
        radius = dp(radius)
        min_height = dp(min_height) if min_height else 0
        # height 必须显式给一个数：Canvas 默认是 "7c"（7 厘米），
        # 会让卡片一开始就莫名其妙地高，也会让读取 height 的代码崩掉。
        super().__init__(parent, bg=outer, highlightthickness=0, bd=0,
                         height=min_height or dp(60), **kw)
        self._pad = pad
        self._radius = radius
        self._bg = bg
        self._outer = outer
        self._min_h = min_height
        self._busy = False
        # ★ 自己记住当前高度，不要去读 Tk 的 height 选项 ——
        #   Canvas 的 height 默认是字符串 "7c"（7 厘米），int() 会直接抛异常。
        self._cur_h = 0

        self.body = tk.Frame(self, bg=bg)

        if title:
            head = tk.Frame(self.body, bg=bg)
            head.pack(fill="x", pady=(0, dp(10)))
            if icon:
                tk.Label(head, text=icon, font=ui_font(12), bg=bg,
                         fg=ACCENT).pack(side="left", padx=(0, 6))
            tk.Label(head, text=title, font=ui_font(11, "bold"), bg=bg,
                     fg=TEXT).pack(side="left")
            self.head = head
        else:
            self.head = None

        self._win = self.create_window(pad, pad, window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._refit)
        self.bind("<Configure>", self._paint)

    def _refit(self, _event=None):
        """内容高度变了 → 调整卡片自身高度。"""
        if self._busy:
            return
        self._busy = True
        try:
            need = max(self._min_h, self.body.winfo_reqheight() + 2 * self._pad)
            if self._cur_h != need:
                self._cur_h = need
                self.configure(height=need)
        finally:
            self._busy = False

    def _paint(self, event=None):
        """重画圆角背景，并把内容宽度对齐到卡片内宽。"""
        w = event.width if event else self.winfo_width()
        h = event.height if event else self.winfo_height()
        if w <= 1 or h <= 1:
            return
        self.delete("cardbg")
        round_rect(self, 0.5, 0.5, w - 0.5, h - 0.5, self._radius,
                   fill=self._bg, outline=BORDER, width=1, tags="cardbg")
        self.tag_lower("cardbg")
        if not self._busy:
            self.itemconfigure(self._win, width=w - 2 * self._pad)


# ===========================================================================
# 指标块（卡片里的一格数据）
# ===========================================================================
class StatTile(tk.Frame):
    """一格数据：小标题 + 大数字 + 单位/副标题。

    颜色可选，用来区分"上传/下载/正常/异常"。
    """

    def __init__(self, parent, label: str, value: str = "0",
                 unit: str = "", icon: str = "", color: str = TEXT,
                 sub: str = "", bg: str = BG_CARD, width: int = 0):
        super().__init__(parent, bg=bg)
        self._bg = bg
        self._label = label
        self._unit = unit

        top = tk.Frame(self, bg=bg)
        top.pack(fill="x")
        if icon:
            tk.Label(top, text=icon, font=ui_font(11), bg=bg, fg=color).pack(
                side="left", padx=(0, dp(5)))
        # 标签字号 10（原来是 9）：中文在小字号下笔画容易糊在一起
        self.lbl = tk.Label(top, text=label, font=ui_font(10), bg=bg, fg=TEXT_SUB)
        self.lbl.pack(side="left")

        row = tk.Frame(self, bg=bg)
        row.pack(fill="x", pady=(dp(3), 0))
        self.val = tk.Label(row, text=value, font=ui_font(16, "bold"),
                            bg=bg, fg=color)
        self.val.pack(side="left")
        self.unit = tk.Label(row, text=unit, font=ui_font(10), bg=bg,
                             fg=TEXT_MUTED)
        self.unit.pack(side="left", padx=(dp(3), 0), pady=(dp(5), 0))

        self.sub = tk.Label(self, text=sub, font=ui_font(9), bg=bg, fg=TEXT_MUTED,
                            anchor="w")
        self.sub.pack(fill="x", pady=(dp(1), 0))

    def set(self, value: str, unit: str = None, color: str = None,
            sub: str = None) -> None:
        self.val.configure(text=value)
        if unit is not None:
            self.unit.configure(text=unit)
        if color is not None:
            self.val.configure(fg=color)
        if sub is not None:
            self.sub.configure(text=sub)


# ===========================================================================
# 流量图表
# ===========================================================================
class TrafficChart(tk.Canvas):
    """双线面积图：上行（橙）/ 下行（蓝），右上角是当前值与峰值。

    为什么用"滚动窗口"而不是按时间轴铺开？
        穿透工具的流量忽高忽低，用户真正关心的是"刚才这几十秒什么样"，
        滚动窗口最直观，也不用处理时间轴刻度。

    ★ 坐标一律取整 —— Canvas 上的文字/线条落在小数坐标时会被抗锯齿
      糊成半透明，看起来就是"字有点虚"。取整后边缘明显更利落。
    """

    def __init__(self, parent, height: int = 168, samples: int = 90,
                 bg: str = BG_CARD, outer: str = BG_CARD):
        super().__init__(parent, height=dp(height), bg=outer,
                         highlightthickness=0, bd=0)
        self._cap = samples
        self._up = []
        self._down = []
        self._bg = bg
        self._hover_index = None
        self._peak_up = 0.0
        self._peak_down = 0.0
        self.bind("<Configure>", lambda _e: self.redraw())
        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", lambda _e: self._set_hover(None))

    def push(self, up: float, down: float) -> None:
        """追加一个采样点（字节/秒）。"""
        up = max(0.0, float(up))
        down = max(0.0, float(down))
        self._up.append(up)
        self._down.append(down)
        # 峰值只在"窗口内"统计：老数据滚出视野后，峰值也该跟着退下去，
        # 否则图上早就看不到的高峰还挂着一个数，反而误导。
        self._peak_up = max(self._up)
        self._peak_down = max(self._down)
        if len(self._up) > self._cap:
            self._up = self._up[-self._cap:]
            self._down = self._down[-self._cap:]
            self._peak_up = max(self._up)
            self._peak_down = max(self._down)

    @property
    def peak(self):
        return self._peak_up, self._peak_down

    def clear(self) -> None:
        self._up.clear()
        self._down.clear()
        self._peak_up = self._peak_down = 0.0
        self.redraw()

    def _set_hover(self, idx):
        if self._hover_index != idx:
            self._hover_index = idx
            self.redraw()

    def _on_motion(self, event):
        """鼠标悬停时显示该采样点的数值。"""
        n = len(self._up)
        if n < 2:
            return self._set_hover(None)
        left, right = self._plot_x()
        if event.x < left - dp(4) or event.x > right + dp(4):
            return self._set_hover(None)
        frac = (event.x - left) / max(1, (right - left))
        idx = int(round(frac * (n - 1)))
        self._set_hover(max(0, min(n - 1, idx)))

    def _plot_x(self):
        return dp(58), max(dp(80), self.winfo_width() - dp(112))

    def _nice_max(self, raw: float) -> float:
        """把 Y 轴上限取整到好看的刻度（1/2/2.5/5 × 10^n）。"""
        raw = max(raw, 16 * 1024)          # 下限 16 KB/s，避免小波动被放大
        exp = 0
        v = raw
        while v >= 10:
            v /= 10.0
            exp += 1
        for step in (1, 2, 2.5, 5, 10):
            if v <= step:
                return step * (10 ** exp)
        return 10 * (10 ** exp)

    def redraw(self) -> None:
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w <= dp(20) or h <= dp(20):
            return

        top = dp(22)
        bottom = h - dp(30)
        left, right = self._plot_x()
        n = len(self._up)
        big = dp(9) >= 10          # 高 DPI 下字号可以大一点

        # ---- Y 轴上限 ----
        peak = max((max(self._up) if self._up else 0),
                   (max(self._down) if self._down else 0))
        ymax = self._nice_max(peak)

        # ---- 网格 + 刻度（坐标全部取整）----
        import protocol as _p
        for i in range(4):
            frac = i / 3.0
            y = int(round(bottom - frac * (bottom - top)))
            self.create_line(left, y, right, y, fill=BORDER_SOFT, width=1)
            self.create_text(left - dp(8), y, anchor="e", fill=TEXT_MUTED,
                             font=mono_font(9 if not big else 10),
                             text=_p.format_bytes(ymax * frac).replace(" ", ""))

        # ---- 基线 ----
        self.create_line(left, int(bottom), right, int(bottom),
                         fill=BORDER, width=1)

        if n < 2:
            self.create_text(int((left + right) / 2), int((top + bottom) / 2),
                             text="等待数据…", fill=TEXT_MUTED, font=ui_font(10))
            self._legend(w, h, 0, 0)
            return

        # ---- 采样点 → 屏幕坐标（整数）----
        span = max(1, right - left)
        height = bottom - top

        def to_xy(series, idx):
            x = int(round(left + span * (idx / (n - 1))))
            y = int(round(bottom - (series[idx] / ymax) * height))
            return x, y

        for series, line_color, fill_color in (
            (self._down, DOWN, DOWN_SOFT),
            (self._up, UP, UP_SOFT),
        ):
            pts = []
            for i in range(n):
                pts.extend(to_xy(series, i))
            # 面积
            area = [pts[0], int(bottom)] + pts + [pts[-2], int(bottom)]
            self.create_polygon(area, fill=fill_color, outline="")
            # 折线
            self.create_line(pts, fill=line_color, width=dp(2) or 2,
                             joinstyle="round")
            # 末端圆点
            r = dp(3) or 3
            self.create_oval(pts[-2] - r, pts[-1] - r, pts[-2] + r, pts[-1] + r,
                             fill=line_color, outline=BG_CARD, width=1)

        # ---- 悬停指示 ----
        if self._hover_index is not None and 0 <= self._hover_index < n:
            i = self._hover_index
            x = int(round(left + span * (i / (n - 1))))
            self.create_line(x, int(top), x, int(bottom),
                             fill="#c7d2e0", dash=(3, 3))
            box = "↑ %s\n↓ %s" % (_p.format_speed(self._up[i]),
                                  _p.format_speed(self._down[i]))
            from_left = x < (left + right) / 2
            self.create_text(x + (dp(10) if from_left else -dp(10)),
                             int(top) + dp(30), text=box,
                             anchor="w" if from_left else "e",
                             fill=TEXT_SUB, font=mono_font(9),
                             justify="left")

        # ---- 时间轴 ----
        self.create_text(left, h - dp(12), anchor="w", fill=TEXT_MUTED,
                         font=ui_font(9), text="%d 秒前" % n)
        self.create_text(right, h - dp(12), anchor="e", fill=TEXT_MUTED,
                         font=ui_font(9), text="现在")

        self._legend(w, h, self._up[-1], self._down[-1])

    def _legend(self, w, h, cur_up, cur_down):
        """右上角图例：色块 + 名称 + 当前值。

        峰值不放在这里 —— 下面已经有独立的"峰值上传/下载"卡片了，
        图例再写一遍只会把这一行挤满（实测长到横跨整个卡片）。
        """
        import protocol as _p
        x = w - dp(12)
        f = ui_font(9)
        measure = tkfont.Font(font=f)
        for label, color, value in (
            ("下行", DOWN, cur_down),
            ("上行", UP, cur_up),
        ):
            txt = "%s %s" % (label, _p.format_speed(value))
            self.create_text(int(x), dp(14), anchor="e", fill=TEXT_SUB,
                             font=f, text=txt)
            tw = measure.measure(txt)
            self.create_oval(int(x - tw - dp(14)), dp(10),
                             int(x - tw - dp(6)), dp(18),
                             fill=color, outline="")
            x -= tw + dp(28)


class NavItem(tk.Frame):
    """侧边栏的一行：图标 + 文字，带悬停/选中效果。"""

    def __init__(self, parent, key: str, text: str, icon: str, command,
                 bg: str = BG_SIDEBAR):
        super().__init__(parent, bg=bg, cursor="hand2")
        self.key = key
        self._bg = bg
        self._command = command
        self._active = False

        self._bar = tk.Frame(self, bg=bg, width=dp(3) or 3)
        self._bar.pack(side="left", fill="y")

        self.inner = tk.Frame(self, bg=bg)
        self.inner.pack(side="left", fill="x", expand=True,
                        padx=(dp(9), dp(8)), pady=dp(9))

        self.icon = tk.Label(self.inner, text=icon, font=ui_font(12),
                             bg=bg, fg=TEXT_SUB, width=2)
        self.icon.pack(side="left")
        self.label = tk.Label(self.inner, text=text, font=ui_font(11),
                              bg=bg, fg=TEXT_SUB, anchor="w")
        self.label.pack(side="left", padx=(dp(5), 0))

        for w in (self, self.inner, self.icon, self.label, self._bar):
            w.bind("<Button-1>", self._on_click)
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)

    def _on_click(self, _e=None):
        self._command(self.key)

    def _on_enter(self, _e=None):
        if not self._active:
            self._paint(BG_HOVER, TEXT)

    def _on_leave(self, _e=None):
        if not self._active:
            self._paint(self._bg, TEXT_SUB)

    def _paint(self, bg, fg):
        for w in (self, self.inner, self.icon, self.label, self._bar):
            w.configure(bg=bg)
        self.icon.configure(fg=ACCENT if self._active else fg)
        self.label.configure(fg=fg)

    def set_active(self, active: bool) -> None:
        self._active = active
        if active:
            self._paint(BG_ACTIVE, ACCENT)
            self.label.configure(font=ui_font(11, "bold"))
            self._bar.configure(bg=ACCENT)
        else:
            self._paint(self._bg, TEXT_SUB)
            self.label.configure(font=ui_font(11))
            self._bar.configure(bg=self._bg)


# ===========================================================================
# 按钮
# ===========================================================================
def make_button(parent, text, command, kind: str = "primary",
                width: int = 0, bg: str = BG_CARD):
    """造一个扁平按钮（tk.Button 在 Windows 上太"古董"，所以用 Label 手做）。

    kind: primary 蓝底白字 / ghost 白底描边 / danger 红字
    """
    if kind == "primary":
        fg, bgc, hover, active = TEXT_ON_ACCENT, ACCENT, ACCENT_DARK, ACCENT_DARK
    elif kind == "danger":
        fg, bgc, hover, active = ERR, BG_CARD, ERR_SOFT, ERR_SOFT
    else:                                   # ghost
        fg, bgc, hover, active = TEXT_SUB, BG_CARD, BG_HOVER, BG_ACTIVE

    lbl = tk.Label(parent, text=text,
                   font=ui_font(10, "bold" if kind == "primary" else "normal"),
                   bg=bgc, fg=fg, padx=dp(17), pady=dp(8), cursor="hand2")
    if width:
        lbl.configure(width=width)
    state = {"disabled": False}

    def on_enter(_e):
        if not state["disabled"]:
            lbl.configure(bg=hover)

    def on_leave(_e):
        if not state["disabled"]:
            lbl.configure(bg=bgc)

    def on_click(_e):
        if not state["disabled"]:
            command()

    lbl.bind("<Enter>", on_enter)
    lbl.bind("<Leave>", on_leave)
    lbl.bind("<Button-1>", on_click)

    def set_state(disabled: bool):
        state["disabled"] = disabled
        lbl.configure(bg=BG_SOFT if disabled else bgc,
                      fg=TEXT_MUTED if disabled else fg,
                      cursor="arrow" if disabled else "hand2")

    def set_text(t: str):
        lbl.configure(text=t)

    lbl.set_state = set_state
    lbl.set_text = set_text
    return lbl


def make_switch(parent, variable, command=None, bg: str = BG_CARD):
    """一个简单的开关（Clash 里那种圆形滑块）。

    用 Canvas 画：底槽 + 圆钮，点击切换。
    """
    W, H, R = dp(46), dp(24), dp(9)
    cv = tk.Canvas(parent, width=W, height=H, bg=bg,
                   highlightthickness=0, bd=0, cursor="hand2")
    state = {"v": bool(variable.get())}

    def paint():
        cv.delete("all")
        on = state["v"]
        track = ACCENT if on else "#cfd8e3"
        m = dp(3)
        round_rect(cv, 1, m, W - 1, H - m, (H - 2 * m) / 2,
                   fill=track, outline="")
        cx = (W - 1 - R - m) if on else (1 + R + m)
        cv.create_oval(cx - R, H / 2 - R, cx + R, H / 2 + R,
                       fill="#ffffff", outline="")

    def toggle(_e=None):
        state["v"] = not state["v"]
        variable.set(state["v"])
        paint()
        if command:
            command(state["v"])

    cv.bind("<Button-1>", toggle)
    paint()
    cv.set_value = lambda v: (state.update(v=bool(v)), paint())
    return cv


# ===========================================================================
# 下拉选择器
# ===========================================================================
class Select(tk.Frame):
    """轻量下拉选择器：显示「当前值 ▾」，点一下弹出选项。

    为什么自绘、不用 ttk.Combobox：
      · ttk 的下拉在 Windows 上是原生浅灰样式，与本项目的圆角卡片风格不搭；
      · 自绘才能给「当前值」上色 —— 黑名单红、白名单绿。
        这正是它存在的理由：一眼就能看出每条规则是拦还是放。

    options   : [(key, label), ...]
    value     : 当前 key
    command   : fn(key)  选中后回调
    color_map : {key: (前景色, 底色)}，缺省用 (fg, bg)
    """

    def __init__(self, parent, options, value, command=None,
                 bg: str = BG_CARD, color_map=None, width: int = 0,
                 font=None, accent_key: str = ""):
        super().__init__(parent, bg=bg, highlightthickness=0, bd=0)
        # 注意：不能叫 self._options —— tkinter 的 Misc._options() 是内部方法，
        # 覆盖掉它会让 pack()/grid() 在取配置时炸掉（'list' object is not callable）。
        self._items = list(options)
        self._labels = {k: v for k, v in self._items}
        self._command = command
        self._color_map = dict(color_map or {})
        self._width = width
        self._font = font or ui_font(10)
        self._value = value if value in self._labels else self._items[0][0]
        # accent_key: 这个 key 加粗显示（用来说明"它是当前生效的那档"）
        self._accent_key = accent_key

        self.label = tk.Label(self, font=self._font, bg=bg, fg=TEXT,
                              padx=dp(10), pady=dp(4), cursor="hand2",
                              anchor="w")
        self.label.pack(fill="x")

        self.menu = tk.Menu(self, tearoff=0, font=self._font,
                            bg=BG_CARD, fg=TEXT,
                            activebackground=ACCENT_SOFT,
                            activeforeground=ACCENT,
                            bd=1, relief="solid")
        for key, text in self._items:
            self.menu.add_command(label=text,
                                  command=lambda k=key: self._choose(k))

        self.label.bind("<Button-1>", self._popup)
        self.label.bind("<Enter>", lambda _e: self._hover(True))
        self.label.bind("<Leave>", lambda _e: self._hover(False))
        self._hover_on = False
        self._paint()

    # ---------------- 绘制 ----------------
    def _paint(self):
        fg, bgc = self._color_map.get(self._value, (TEXT, BG_SOFT))
        weight = "bold" if self._value == self._accent_key else "normal"
        self.label.configure(
            text="%s ▾" % self._labels[self._value],
            fg=fg, bg=self._mix(bgc) if self._hover_on else bgc,
            font=ui_font(10, weight))
        if self._width:
            self.label.configure(width=self._width)

    @staticmethod
    def _mix(color: str) -> str:
        """把底色稍微压深一点，做悬停反馈（不引额外依赖）。"""
        try:
            rgb = (int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16))
        except (ValueError, IndexError):
            return color
        return "#%02x%02x%02x" % tuple(max(0, c - 8) for c in rgb)

    def _hover(self, on: bool):
        self._hover_on = on
        self._paint()

    # ---------------- 交互 ----------------
    def _popup(self, event):
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _choose(self, key):
        # 先关闭菜单再回调：回调里会 _render_rules() 重建整页，
        # 如果菜单还处于 popup 状态，销毁它会留下一个抓不到释放的 grab。
        try:
            self.menu.unpost()
        except tk.TclError:
            pass
        self.set_value(key)
        if self._command:
            self._command(key)

    # ---------------- 对外 ----------------
    def get(self) -> str:
        return self._value

    def set_value(self, key):
        if key in self._labels:
            self._value = key
            self._paint()

    def set_accent(self, key: str):
        """标记哪一档是"当前生效"的（加粗）。"""
        self._accent_key = key
        self._paint()


def make_select(parent, options, value, command=None, bg: str = BG_CARD,
                color_map=None, width: int = 0, font=None,
                accent_key: str = ""):
    """造一个下拉选择器（见 Select）。"""
    return Select(parent, options, value, command, bg, color_map,
                  width, font, accent_key)
