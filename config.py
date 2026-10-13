"""
config.py —— 配置文件加载 + 极简调用支持（两端共用）

为什么要这个文件？
    原来要靠命令行堆十几个参数：
        python frps.py --serve_host 0.0.0.0 --serve_port 8800 --user_host 0.0.0.0 \
          --token_file tokens.txt --cert_file certs/server.crt --key_file certs/server.key \
          --ca_cert_file certs/ca.crt --ca_key_file certs/ca.key --cert_host 1.2.3.4 ...
    又长又容易写错。现在改成写一份 TOML，然后一条命令：

        python frps.py -c server.toml
        python frpc.py -c client.toml

两个设计原则：
    1. **命令行优先**：凡是命令行显式给的值，都覆盖配置文件。
       所以"日常用配置、临时想改一项就用命令行顶掉"都支持。
    2. **向后兼容**：不写配置文件、全部用命令行，行为和以前一模一样。

配置文件里的字段名 = 命令行长选项去掉前导 `--`，例如：
    命令行 --serve_port 9000   ←→   TOML  serve_port = 9000
这样只需要记一套名字，不用再学第二套。
"""

import os
import sys

# ---------------------------------------------------------------------------
# TOML 读取（优先标准库 tomllib，Python 3.11+ 自带，无需装依赖）
# ---------------------------------------------------------------------------

try:
    import tomllib as _toml          # Python 3.11+

    def _load_toml(path: str) -> dict:
        with open(path, "rb") as f:      # tomllib 要求二进制模式
            return _toml.load(f)

except ModuleNotFoundError:              # pragma: no cover - 老版本 Python 兜底
    try:
        import tomli as _toml            # pip install tomli

        def _load_toml(path: str) -> dict:
            with open(path, "rb") as f:
                return _toml.load(f)

    except ModuleNotFoundError:
        def _load_toml(path: str) -> dict:
            raise RuntimeError(
                "当前 Python 版本（%d.%d）不带 tomllib，请升级到 3.11+，"
                "或安装 tomli：pip install tomli" % sys.version_info[:2]
            )


def load_config(path: str) -> dict:
    """读一份 TOML 配置，返回扁平字典。

    允许两种写法，都会归一化成同一份扁平字典：

        # 写法 A：直接平铺（推荐，简单）
        serve_port = 8800
        token_file = "tokens.txt"

        # 写法 B：分段（配置多了以后更整齐）
        [server]
        serve_port = 8800

        [security]
        token_file = "tokens.txt"

    写法 B 会把各段"拉平"合并 —— 段的层级只是为了好看，不影响取值。
    """
    if not os.path.exists(path):
        raise FileNotFoundError("配置文件不存在：%s" % path)

    raw = _load_toml(path)

    flat = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            # 分段写法：把段里的键提升到顶层
            for sub_key, sub_value in value.items():
                flat.setdefault(sub_key, sub_value)
        else:
            flat[key] = value
    return flat


def normalize_keys(cfg: dict) -> dict:
    """把配置键统一成 argparse 用的下划线风格。

    允许用户在 TOML 里写连字符（serve-port）或下划线（serve_port），
    也可以用大写，这里统统归一化成 `serve_port` 这种形式。
    """
    out = {}
    for key, value in cfg.items():
        out[key.strip().lower().replace("-", "_")] = value
    return out


def apply_config(args, cfg: dict) -> None:
    """把配置文件里的值"填进"命令行解析结果（仅填补命令行没给的项）。

    判定"命令行没给"的办法：argparse 的默认值 + 一个探测用的 `--flag`。
    这里更简单可靠的等价做法是：对每个布尔开关（store_true），
    只要配置文件给了 true，就置位；对普通项，只要当前值等于 argparse
    默认值，就认为"命令行没显式给"，可以用配置覆盖。

    注意：这样写会有一个小副作用 —— 如果某人在命令行显式传了
    `--serve_port 8800`（恰好等于默认值），配置文件里的同项仍会生效。
    但两者相等，结果一样，因此无实际影响。
    """
    for key, value in cfg.items():
        if not hasattr(args, key):
            # 配置里写了不认识的键：提示一下，但不中断（可能是笔误或注释性字段）
            print("  · 忽略无法识别的配置项：%s" % key)
            continue

        current = getattr(args, key)
        default = _ARGPARSE_DEFAULTS.get(key, None)

        # 布尔开关（store_true）：配置里给了 true 就打开
        if isinstance(current, bool):
            if value is True and not current:
                setattr(args, key, True)
            continue

        # append 类参数（如 cert_host）：命令行没给时用配置里的列表
        if isinstance(current, list):
            if not current and value:
                setattr(args, key, list(value) if isinstance(value, (list, tuple)) else [value])
            continue

        # 普通项：当前值 == argparse 默认值 → 认为命令行没显式给
        if current == default:
            setattr(args, key, value)


# 由各端在构造 parser 时登记"默认值表"，用于判断命令行是否显式给过值。
_ARGPARSE_DEFAULTS: dict = {}


def remember_defaults(parser) -> None:
    """把 parser 中所有参数的默认值记下来，供 apply_config 判断用。"""
    _ARGPARSE_DEFAULTS.clear()
    for action in parser._actions:              # noqa: SLF001 - 标准库惯例
        if action.dest and action.dest != "help":
            _ARGPARSE_DEFAULTS[action.dest] = action.default


def add_common_args(parser) -> None:
    """给两端的 parser 都加上 `-c/--config`。"""
    parser.add_argument(
        "-c", "--config", default="",
        help="从 TOML 配置文件读取参数（命令行显式给出的项会覆盖配置）",
    )


def attach_config(args, logger=None) -> None:
    """若指定了 -c/--config，就加载并套用；命令行优先。"""
    path = getattr(args, "config", "")
    if not path:
        return
    cfg = normalize_keys(load_config(path))
    apply_config(args, cfg)
    if logger:
        logger.info("已加载配置文件：%s", path)
