"""
make_icon.py —— 从源图生成程序图标（assets/icon.ico + icon.png）

什么时候需要跑这个？
    只有你想换图标时才需要。仓库里已经带了生成好的 assets/icon.ico，
    `python build_exe.py` 会直接用它，**日常打包不用跑本脚本**。

换图标怎么做？
    1. 把新图存成 assets/icon-source.jpg（或改下面的 SRC 路径）
    2. python make_icon.py
    3. python build_exe.py

为什么要自动检测徽标边界，而不是写死圆角半径？
    源图是 JPEG，边缘有压缩噪点；写死数值一旦偏差，
    图标四角就会露出黑色直角（在浅色桌面上非常显眼）。
    这里改成"检测徽标描边"来定位边界，再据此构造抗锯齿圆角蒙版，
    换一张构图类似的图也能自动适配。

产出：
    assets/icon.ico        —— exe 图标（资源管理器/桌面/任务栏）
    assets/icon.png        —— 运行期窗口与任务栏图标（256px）
    assets/icon-1024.png   —— 带透明通道的母版
    assets/_preview.png    —— 各尺寸预览（浅底/深底，仅供人工检查）
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
SRC = os.path.join(ASSETS, "icon-source.jpg")

SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]


def main() -> int:
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        sys.stderr.write(
            "缺少 Pillow，无法生成图标。请先安装：\n"
            "    pip install pillow\n"
            "（若只是要打包，仓库里的 assets/icon.ico 已够用，不必跑本脚本）\n")
        return 2

    if not os.path.exists(SRC):
        sys.stderr.write("找不到源图：%s\n" % SRC)
        return 1
    os.makedirs(ASSETS, exist_ok=True)

    im = Image.open(SRC).convert("RGB")
    W, H = im.size
    gray = im.convert("L")
    gp = gray.load()
    print("源图: %dx%d" % (W, H))

    # ---------- 1) 检测徽标描边位置 ----------
    def brightest_on_line(fixed, is_column, lo, hi):
        """在一条直线上找最亮像素 —— 徽标的浅色描边比周围暗背景亮得多。"""
        best_v, best_p = -1, None
        for p in range(lo, hi):
            v = gp[fixed, p] if is_column else gp[p, fixed]
            if v > best_v:
                best_v, best_p = v, p
        return best_p, best_v

    top_y, t1 = brightest_on_line(W // 2, True, 0, 80)
    left_x, t2 = brightest_on_line(H // 2, False, 0, 80)
    print("描边检测: 上边 y=%s(亮度%d)  左边 x=%s(亮度%d)" % (top_y, t1, left_x, t2))

    # 对角线上的描边位置，用来反推圆角半径
    best_d, best_dv = -1, -1
    for d in range(0, 200):
        v = gp[d, d]
        if v > best_dv:
            best_dv, best_d = v, d
    print("对角线描边位置: d=%d (亮度%d)" % (best_d, best_dv))

    # 圆角矩形：描边中心线在对角线上满足 d = inset + 0.2929R
    # （0.2929 = 1 - 1/√2，是 45° 方向从角点到圆弧的距离系数）
    inset = (top_y + left_x) / 2.0
    R = (best_d - inset) / 0.2929 if best_d > inset else 0

    # 稍微外扩一点，让蒙版压住描边外缘，避免露出黑直角
    PAD = 1.5
    box = (inset - PAD, inset - PAD, W - inset + PAD, H - inset + PAD)
    radius = R + PAD
    print("推算: 内缩 %.1f px, 圆角半径 %.1f px (占 %.1f%%)" %
          (inset, R, R / W * 100))
    print("蒙版: box=%s radius=%.1f" % (tuple(round(v, 1) for v in box), radius))

    # ---------- 2) 抗锯齿圆角蒙版（4 倍超采样后缩小）----------
    SS = 4
    mask = Image.new("L", (W * SS, H * SS), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [box[0] * SS, box[1] * SS, box[2] * SS, box[3] * SS],
        radius=radius * SS, fill=255,
    )
    mask = mask.resize((W, H), Image.LANCZOS)

    master = im.convert("RGBA")
    master.putalpha(mask)
    master.save(os.path.join(ASSETS, "icon-1024.png"))

    # 256px：运行期窗口/任务栏图标
    master.resize((256, 256), Image.LANCZOS).save(os.path.join(ASSETS, "icon.png"))

    # ---------- 3) 多尺寸 ICO ----------
    ico_path = os.path.join(ASSETS, "icon.ico")
    master.save(ico_path, format="ICO", sizes=[(s, s) for s in SIZES])
    print("已生成 icon.ico（尺寸 %s），%.1f KB" %
          (",".join(str(s) for s in SIZES), os.path.getsize(ico_path) / 1024))

    # ---------- 4) 预览图（浅底 + 深底，检查圆角有没有露黑边）----------
    def strip(bg):
        pad, cell = 14, 148
        cv = Image.new("RGB", (cell * len(SIZES) + pad * 2, cell + pad * 2), bg)
        for i, s in enumerate(SIZES):
            fr = master.resize((s, s), Image.LANCZOS)
            show = fr.resize((cell - 20, cell - 20), Image.NEAREST)
            cv.paste(show, (pad + i * cell + 10, pad + 10), show)
        return cv

    a, b = strip((245, 245, 248)), strip((32, 36, 44))
    pv = Image.new("RGB", (a.width, a.height * 2 + 8), (128, 128, 128))
    pv.paste(a, (0, 0))
    pv.paste(b, (0, a.height + 8))
    pv.save(os.path.join(ASSETS, "_preview.png"))

    print("已生成 icon.png / icon-1024.png / _preview.png（上=浅底 下=深底）")
    print("完成。接着跑 python build_exe.py 即可把图标打进 exe。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
