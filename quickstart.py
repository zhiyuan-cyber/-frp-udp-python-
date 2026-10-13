"""
quickstart.py —— 一键生成配置 + 证书，把上手成本压到最低

用法（第一次）：
    python quickstart.py server        # 生成 server.toml + certs/ + tokens.txt
    python quickstart.py client        # 生成 client.toml

它做的事：
    1. 若 certs/ 里没有证书，自动调 gen_cert.py 生成一套（含自动续期要用的 ca.key）
    2. 若 tokens.txt 不存在，生成一个随机 token 写进去
    3. 若 server.toml / client.toml 不存在，写出一份带注释的模板
    4. 已存在的文件**不覆盖**，避免把你改好的配置冲掉

生成完直接：
    python frps.py -c server.toml
    python frpc.py -c client.toml
"""

import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(HERE, "certs")
TOKEN_FILE = os.path.join(HERE, "tokens.txt")

SERVER_TEMPLATE = """\
# frps 服务端配置 —— 由 quickstart.py 生成，可按需修改
# 用法： python frps.py -c server.toml

[server]
serve_host = "0.0.0.0"
serve_port = 8800
user_host  = "0.0.0.0"

[security]
token_file   = "tokens.txt"          # 改这个文件即可轮换 token（自动热重载）
cert_file    = "certs/server.crt"
key_file     = "certs/server.key"
ca_cert_file = "certs/ca.crt"        # 证书自动续期用
ca_key_file  = "certs/ca.key"
cert_host       = ["{host}", "localhost"]   # ← 改成你的公网 IP / 域名
cert_renew_days = 30

[limits]
max_conn_per_ip  = 20
max_active_conns = 100
max_queued       = 50

[udp]
# UDP 转发限流（有客户端启用 udp_port 时才生效）
max_udp_sessions    = 512   # 单客户端最大并发 UDP 会话数（按外部来源地址计）
udp_session_timeout = 60    # UDP 会话空闲多少秒后回收
# udp_target_addr   = ""    # 一般留空，由客户端用自己的 local_host

[p2p]
# 是否允许客户端做 UDP 打洞探测（失败会自动回退到中转，无副作用）
no_p2p = false

[log]
log_level = "INFO"
"""

CLIENT_TEMPLATE = """\
# frpc 客户端配置 —— 由 quickstart.py 生成，可按需修改
# 用法： python frpc.py -c client.toml

[server]
serve_host = "{host}"     # ← 改成你的公网服务器地址
serve_port = 8800

[local]
local_host = "127.0.0.1"  # 要被穿透的本机服务
local_port = 8080         # ← 改成你的服务端口

[identity]
proxy_name  = "myapp"     # ← 多客户端时每个都要唯一
remote_port = 9001        # ← 在服务端占用的对外 TCP 端口

[udp]
# 需要穿透 UDP 服务时打开（DNS / 游戏 / RDP-UDP 等）
# udp_port       = 9001   # ← 在服务端占用的对外 UDP 端口（可与 TCP 同号）
# udp_local_port = 8080   # ← 本机 UDP 服务端口（默认与 local_port 相同）

[p2p]
# 打洞探测（失败会自动回退到中转，不影响可用性）
no_p2p      = false
p2p_timeout = 3.0         # 打洞最长等待秒数，超时即走中转

[security]
token_file = "tokens.txt" # 和服务端用同一份 token 文件（或直接写 token = "..."）
ca_file    = "certs/ca.crt"

[log]
log_level = "INFO"
"""


def ensure_certs(host: str) -> None:
    """没有证书就生成一套（复用 gen_cert.py，保证逻辑一致）。"""
    need = ["ca.crt", "ca.key", "server.crt", "server.key"]
    if all(os.path.exists(os.path.join(CERT_DIR, f)) for f in need):
        print("  · 证书已存在，跳过：certs/")
        return
    print("  · 正在生成证书（含自动续期所需的 ca.key）……")
    import subprocess
    subprocess.run(
        [sys.executable, os.path.join(HERE, "gen_cert.py"),
         "--host", host, "--host", "localhost", "--out", CERT_DIR],
        check=True,
    )


def ensure_token() -> str:
    """没有 tokens.txt 就生成一个随机 token。"""
    if os.path.exists(TOKEN_FILE):
        first = ""
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    first = line
                    break
        print("  · token 文件已存在，跳过：tokens.txt")
        return first
    token = secrets.token_urlsafe(24)      # 强随机，URL 安全
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write("# 每行一个 token，# 开头为注释，首行为主 token\n")
        f.write("# 轮换时：把新 token 写在最上面，旧 token 暂留一行，\n")
        f.write("#         等所有客户端都换完再删掉旧的那行（无需重启服务端）\n")
        f.write(token + "\n")
    print("  · 已生成随机 token → tokens.txt")
    return token


def write_template(path: str, template: str) -> None:
    """模板文件只在不存在时写，避免覆盖用户改过的配置。"""
    name = os.path.basename(path)
    if os.path.exists(path):
        print("  · 配置已存在，未覆盖：%s" % name)
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(template)
    print("  · 已生成配置模板：%s" % name)


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in ("server", "client"):
        print(__doc__)
        return 2

    host = ""
    for i, a in enumerate(sys.argv[2:]):
        if a in ("--host", "-H") and i + 3 <= len(sys.argv) - 1:
            host = sys.argv[i + 3]
    host = host or input("请输入你的公网 IP / 域名（直接回车用 127.0.0.1）: ").strip() or "127.0.0.1"

    print("正在准备 %s 端……" % ("服务端" if mode == "server" else "客户端"))
    ensure_certs(host)
    token = ensure_token()

    if mode == "server":
        write_template(os.path.join(HERE, "server.toml"), SERVER_TEMPLATE.format(host=host))
        print()
        print("下一步：  python frps.py -c server.toml")
    else:
        write_template(os.path.join(HERE, "client.toml"), CLIENT_TEMPLATE.format(host=host))
        print()
        print("下一步：  python frpc.py -c client.toml")
    print()
    print("提示：token 文件里的主 token = %s" % (token or "(见 tokens.txt)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
