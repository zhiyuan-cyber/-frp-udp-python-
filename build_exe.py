"""
build_exe.py —— 把 GUI 版打包成单文件 exe

产物：
    dist/内网穿透助手.exe      （双击即用，目标机器无需安装 Python）

为什么要 --onefile？
    一个文件最好传播：拷到 U 盘、发给同事、丢到服务器上都能直接双击。
    代价是首次启动要先把自身解压到临时目录（约 1-2 秒）。

为什么 --noconsole？
    这是图形程序，弹一个黑色命令框很丑。日志在窗口里看。

作者信息：
    姓名 / 邮箱 / 主页 统一来自 about.py，本脚本会自动：
        1. 生成 Windows 版本资源文件（version_info.txt）并交给 PyInstaller，
           于是 exe 的「右键 → 属性 → 详细信息」里能看到作者、版权等信息；
        2. 界面里的署名与「关于」对话框也读同一份 about.py。
    所以换作者/改邮箱只需改 about.py 一处，下次编译自动生效。

注意事项（踩过的坑）：
    · tkinter 的 tcl/tk 资源必须一起打包，否则 exe 启动就报
      "Can't find a usable init.tcl"。PyInstaller 一般能自动带上，
      但用某些精简版 Python 时会漏 —— 所以本脚本会显式检查。
    · cryptography 的体积主要来自 _rust.abi3.pyd，属正常现象。
    · 数据目录（certs/、tokens.txt）不打包进 exe：
      它们在运行时生成到 exe 所在目录，方便查看与备份。
    · 打包用的 Python 必须自带 tkinter（本机只有系统 Python 3.14 有，
      托管 3.13 没有），否则打出来的是无界面程序。
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import about  # noqa: E402  （作者信息的唯一来源）

NAME = about.APP_NAME
ENTRY = os.path.join(HERE, "gui.py")
DIST = os.path.join(HERE, "dist")
BUILD = os.path.join(HERE, "build")
VERSION_FILE = os.path.join(HERE, "version_info.txt")

# 这些模块必须显式声明，因为它们是"运行期才 import"的，
# PyInstaller 的静态分析看不到（gui.py 里用 import frps / import frpc 延迟导入）。
HIDDEN = [
    "frps", "frpc", "protocol", "config", "gen_cert", "cert_renew", "about",
    "tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox",
    "cryptography", "cryptography.hazmat.backends.openssl",
    "asyncio", "ssl", "sqlite3",
]

# 明确排除，给 exe 瘦身（这些是本机其他项目用的，跟本程序无关）
EXCLUDE = [
    "numpy", "pandas", "matplotlib", "PIL", "PyQt5", "PySide2",
    "IPython", "jupyter", "pytest", "setuptools", "pip",
    "scipy", "lxml", "bs4", "requests",
]

# 打包时留在 exe 旁边、方便用户查看的文件（可选）
BUNDLE_EXTRAS = ["README.md"]


def check_env() -> None:
    """打包前先确认环境齐备，给出可读的中文错误。"""
    missing = []
    for mod in ("PyInstaller", "cryptography", "tkinter"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        sys.stderr.write(
            "缺少依赖：%s\n"
            "请先安装：pip install %s\n"
            "（注意 tkinter 通常需用带 tcl/tk 的完整版 Python；\n"
            " 本机托管 Python 3.13 不带 tkinter，请用系统 Python 3.14 的 venv）\n"
            % (", ".join(missing), " ".join(missing).lower())
        )
        raise SystemExit(2)
    print("环境检查通过：PyInstaller / cryptography / tkinter 均在位")
    print("作者信息：%s" % about.summary())


def _ver_tuple(text: str) -> tuple:
    """把 '1.2.3' 转成 (1, 2, 3, 0)，PyInstaller 要求 4 段整数。"""
    parts = []
    for x in str(text).split(".")[:4]:
        try:
            parts.append(int(x))
        except ValueError:
            parts.append(0)
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def write_version_file() -> str:
    """生成 Windows 版本资源文件 —— 让 exe 属性里显示作者/版权。

    这是"把作者信息写进产物"最实在的一步：
    即使不看界面，右键 exe → 属性 → 详细信息 也能看到是谁做的。

    格式要求（PyInstaller 的 version-file）：
        · 必须定义 VSVersionInfo / FixedFileInfo / StringFileInfo 等名字；
        · 中文字符串表用 langid=2052（简体中文）+ charset=1200（Unicode），
          对应 StringTable 的键 '080404b0'。
    """
    v = _ver_tuple(about.APP_VERSION)
    content = """\
# 由 build_exe.py 自动生成，请勿手工修改 —— 改 about.py 即可
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=%(v)s,
    prodvers=%(v)s,
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '080404b0',
        [StringStruct('CompanyName', '%(author)s'),
         StringStruct('FileDescription', '%(desc)s'),
         StringStruct('FileVersion', '%(ver)s'),
         StringStruct('InternalName', '%(name)s'),
         StringStruct('LegalCopyright', '%(copy)s'),
         StringStruct('OriginalFilename', '%(name)s.exe'),
         StringStruct('ProductName', '%(name)s'),
         StringStruct('ProductVersion', '%(ver)s'),
         StringStruct('Comments', '作者主页 %(home)s | 邮箱 %(mail)s')])
    ]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
""" % {
        "v": v,
        "ver": about.APP_VERSION,
        "name": NAME,
        "author": about.AUTHOR_NAME,
        "desc": about.APP_DESCRIPTION,
        "copy": about.COPYRIGHT,
        "home": about.AUTHOR_HOMEPAGE,
        "mail": about.AUTHOR_EMAIL,
    }
    with open(VERSION_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    print("已生成版本资源：%s（写入作者 %s）" % (
        os.path.basename(VERSION_FILE), about.AUTHOR_NAME))
    return VERSION_FILE


def build() -> None:
    # ★★ 千万不要 shutil.rmtree(dist) ★★
    #   dist/ 里除了本程序（exe），还放着**运行时生成的凭据**：
    #     certs/ca.crt、certs/server.crt、server.key、tokens.txt
    #   一旦整目录删掉，服务端身份就没了 —— 客户端那边还拿着旧的 ca.crt，
    #   重连会全部失败（而且用户完全看不出原因）。
    #   另外实测：本机安全策略会拦截"整目录删除"，报
    #     [safe-delete] ... Error during a `trash` operation
    #   直接把打包打断。
    #   所以这里**一个文件都不删**：交给 PyInstaller 用 --noconfirm 原地覆盖 exe。
    #   （本机安全策略会把"删除"重定向到回收站，回收站操作在沙箱里会失败，
    #     连 os.remove 都会被拦；原地覆盖则完全不走删除路径。）
    os.makedirs(DIST, exist_ok=True)

    # 工作目录是纯中间产物，可再生，删掉没问题
    shutil.rmtree(BUILD, ignore_errors=True)

    vfile = write_version_file()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile",
        "--noconsole",
        "--name", NAME,
        "--distpath", DIST,
        "--workpath", BUILD,
        "--specpath", HERE,
        # 把项目源码目录整体纳入搜索路径，便于 import frps / frpc
        "--paths", HERE,
        # ★ 作者信息写进 exe 文件属性
        "--version-file", vfile,
    ]
    for h in HIDDEN:
        cmd += ["--hidden-import", h]
    for e in EXCLUDE:
        cmd += ["--exclude-module", e]
    for x in BUNDLE_EXTRAS:
        p = os.path.join(HERE, x)
        if os.path.exists(p):
            cmd += ["--add-data", "%s%s." % (p, os.pathsep)]
    cmd.append(ENTRY)

    print("开始打包（首次较慢，请耐心等待）……")
    proc = subprocess.run(cmd, cwd=HERE)
    if proc.returncode != 0:
        sys.stderr.write("打包失败，退出码 %d\n" % proc.returncode)
        raise SystemExit(proc.returncode)

    exe = os.path.join(DIST, NAME + ".exe")
    if not os.path.exists(exe):
        sys.stderr.write("没有找到产物：%s\n" % exe)
        raise SystemExit(1)
    size_mb = os.path.getsize(exe) / 1024 / 1024
    print("\n打包完成：%s（%.1f MB）" % (exe, size_mb))
    print("作者信息已写入：")
    print("  · 程序界面底部署名 + 「帮助 → 关于」对话框")
    print("  · exe 文件属性（右键 → 属性 → 详细信息）")
    print("    %s" % about.summary())
    print("提示：dist/ 内的 certs/ 与 tokens.txt 属于运行时凭据，本次未做任何改动。")


if __name__ == "__main__":
    check_env()
    build()
