"""
about.py —— 程序信息与作者信息（单一来源）

为什么要单独一个文件？
    作者信息同时出现在三个地方：
        1. 图形界面（「关于」对话框 + 底部页脚）
        2. 打包出来的 exe 的文件属性（右键 → 属性 → 详细信息）
        3. README 与命令行 --version
    如果各处分别硬编码，改了名字或邮箱就一定会漏掉某处。
    统一放这里，改一行就全生效 —— 下次编译自动带上新信息。

作者信息：
    姓名   jsdczd任志远
    邮箱   mailrzy@126.com
    主页   https://github.com/zhiyuan-cyber
"""

# ---- 作者信息（改这里即可，全项目生效）----
AUTHOR_NAME = "jsdczd任志远"
AUTHOR_EMAIL = "mailrzy@126.com"
AUTHOR_HOMEPAGE = "https://github.com/zhiyuan-cyber"

# ---- 程序信息 ----
APP_NAME = "内网穿透助手"
APP_TITLE = "内网穿透助手  ·  FRP 图形版"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "基于 asyncio 的 FRP 内网穿透（token 鉴权 + TLS + 限流 + 统计）"

# ---- 展示用文本（界面与命令行共用，避免多处拼接不一致）----
COPYRIGHT = "© 2026 %s" % AUTHOR_NAME


def author_lines() -> "list[tuple[str, str]]":
    """返回 [(标签, 值), ...]，供界面逐行展示。"""
    return [
        ("作者", AUTHOR_NAME),
        ("邮箱", AUTHOR_EMAIL),
        ("主页", AUTHOR_HOMEPAGE),
    ]


def summary() -> str:
    """一行式摘要，供日志/命令行使用。"""
    return "%s v%s  |  作者 %s  |  %s  |  %s" % (
        APP_NAME, APP_VERSION, AUTHOR_NAME, AUTHOR_EMAIL, AUTHOR_HOMEPAGE)


if __name__ == "__main__":
    # 直接运行本文件可快速确认信息（也用于打包脚本自检）
    print(summary())
    for k, v in author_lines():
        print("  %s：%s" % (k, v))
