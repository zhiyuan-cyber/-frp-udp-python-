"""
mobile_api.py —— 手机控制接口（供鸿蒙 App 使用）

为什么需要这个文件？
    鸿蒙系统**不支持运行 Python**，官方应用语言只有 ArkTS / C++。
    所以「内网穿透助手」的穿透引擎只能继续跑在电脑上，
    手机端做成一个**远程控制台**：查看状态 / 日志 / 连接，
    并远程启停服务、增删过滤规则。

    本模块就是在电脑端开一个极小的 HTTP 服务，把已有能力用 JSON 暴露出去。
    鸿蒙 App 通过它通信（见 harmonyos/ 目录）。

安全设计（务必注意）：
    · 默认**只监听回环地址**，要手机能连需显式 --mobile-api-host 0.0.0.0；
    · 每个请求必须带 `X-Frp-Token` 头，令牌每次启动随机生成并打印在日志里；
    · 令牌比较用 hmac.compare_digest（防时序攻击）；
    · 只实现 GET/POST 的白名单路由，不提供文件读写、不执行任意命令。
    即便如此，把控制端口暴露到公网仍有风险 —— 建议只在局域网内使用。
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOG = logging.getLogger("mobile")

# 手机端一次最多拉多少条日志（防止手机内存被日志撑爆）
MAX_LOG_LIMIT = 2000
# 控制接口能读取的日志文件保留天数（与 gui.LOG_RETAIN_DAYS 一致）
LOG_RETAIN_DAYS = 7


def new_token() -> str:
    """生成访问令牌：随机 + 时间戳，够用且便于日志里辨认。"""
    raw = secrets.token_hex(4)
    return "%s-%s" % (time.strftime("%H%M%S"), raw)


class ControlBridge:
    """把界面（主线程）的能力桥接给 HTTP 线程。

    为什么用"回调注入"而不是直接 import gui？
        mobile_api 是独立的传输层，不该反向依赖 GUI；
        而且测试时可以用假对象替代，不必真的起界面。
    """

    def __init__(self, rules, rules_file, log_dir, data_dir,
                 start_server=None, stop_server=None,
                 start_client=None, stop_client=None,
                 stats_provider=None, links_provider=None,
                 info_provider=None, busy_provider=None):
        self.rules = rules                          # rules.RuleSet
        self.rules_file = rules_file
        self.log_dir = log_dir
        self.data_dir = data_dir
        self._start_server = start_server           # 回调：启动服务端
        self._stop_server = stop_server
        self._start_client = start_client
        self._stop_client = stop_client
        self._stats = stats_provider or (lambda: {})
        self._links = links_provider or (lambda: [])
        self._info = info_provider or (lambda: {})
        self._busy = busy_provider or (lambda: False)

    # ---------------- 状态 ----------------
    def state(self) -> dict:
        stats = self._stats() or {}
        role = stats.get("_role", "idle")
        running = bool(stats.get("_running", False))
        return {
            "role": role,
            "running": running,
            "uptime": stats.get("uptime", 0),
            "clients": stats.get("clients", stats.get("connections_active", 0)),
            "tunnels": stats.get("tunnels_established", 0),
            "connections": stats.get("connections_active", 0),
            "connectionsPeak": stats.get("connections_peak", 0),
            "bytesUp": stats.get("bytes_up", 0),
            "bytesDown": stats.get("bytes_down", 0),
            "speedUp": stats.get("_speed_up", 0),
            "speedDown": stats.get("_speed_down", 0),
            "rejected": (stats.get("rejected_overload", 0)
                         + stats.get("rejected_timeout", 0)
                         + stats.get("rejected_offline", 0)),
            "authFailed": stats.get("auth_failures", 0),
        }

    def connections(self) -> list:
        """正在转发的连接明细（字段名与鸿蒙端 Models.ets 对齐）。"""
        out = []
        for c in (self._links() or []):
            peer = c.get("peer") or "-"
            target = c.get("target") or "-"
            # frps 侧没有 target（它是"外部用户 IP:端口"），这里补一个可读值
            if target in ("-", "", None):
                target = peer
            out.append({
                "name": c.get("proxy") or "tunnel",
                "peer": peer,
                "target": target,
                "bytesUp": c.get("bytes_up", 0),
                "bytesDown": c.get("bytes_down", 0),
                "duration": c.get("elapsed", 0),
                "since": time.strftime("%m-%d %H:%M:%S",
                                       time.localtime(c.get("started", time.time()))),
            })
        return out

    def server_info(self) -> dict:
        info = self._info() or {}
        return {
            "publicIp": info.get("public_ip") or info.get("ip") or "-",
            "geo": info.get("geo") or info.get("location") or "-",
            "isp": info.get("isp") or "-",
            "latencyMs": info.get("latency") or info.get("latency_ms") or 0,
            "localPorts": info.get("ports") or [],
        }

    # ---------------- 规则 ----------------
    def rules_payload(self) -> dict:
        items = []
        for idx, r in enumerate(self.rules.rules):
            items.append({
                "index": idx,
                "host": r.host,
                "ports": r.port,
                # 每条规则自带类型（黑名单/白名单），不再由全局模式推算 ——
                # 黑白混排时手机端也要能看出哪条在拦、哪条在放。
                # 手机端沿用黑名单/白名单叫法，电脑端内部是 deny/allow。
                "action": "allow" if getattr(r, "is_allow", False) else "deny",
                "note": r.note or "",
                "enabled": bool(getattr(r, "enabled", True)),
            })
        return {
            # 电脑端内部叫 blocklist/allowlist，手机端用 blacklist/whitelist，
            # 这里统一成手机端的叫法，避免两端各写一套映射。
            # 注意：它表示的是「默认策略」（未命中任何规则时怎么办），
            # 不是整张表的类型 —— 规则类型逐条看每条自己的 action。
            "mode": "whitelist" if self.rules.mode == "allowlist" else "blacklist",
            "enabled": bool(self.rules.enabled),
            "rules": items,
        }

    def add_rule(self, host: str, ports: str, note: str = "",
                 action: str = "deny") -> None:
        self.rules.add(host or "*", ports or "*", note or "", action=action)
        self.rules.save(self.rules_file)

    def remove_rule(self, index: int) -> bool:
        ok = self.rules.remove(index)
        if ok:
            self.rules.save(self.rules_file)
        return ok

    def set_rule_action(self, index: int, action: str) -> bool:
        """改某条规则的类型（黑名单/白名单）。"""
        ok = self.rules.set_action(index, action)
        if ok:
            self.rules.save(self.rules_file)
        return ok

    def set_rule_mode(self, mode: str, enabled=None) -> None:
        """设置默认策略（未命中任何规则时：放行 / 拒绝）与总开关。"""
        self.rules.mode = "allowlist" if mode in ("whitelist", "allowlist") else "blocklist"
        if enabled is not None:
            self.rules.enabled = bool(enabled)
        self.rules.save(self.rules_file)

    # ---------------- 日志 ----------------
    def logs(self, level: str = "ALL", keyword: str = "", limit: int = 400) -> list:
        """读取最近 7 天的日志，按级别与关键字过滤后返回最新 limit 条。

        行格式：2026-10-14 15:46:16 [INFO] gui: 消息
        """
        limit = max(1, min(int(limit or 400), MAX_LOG_LIMIT))
        lines = self._read_recent_lines(limit * 12)
        out = []
        want = (level or "ALL").upper()
        kw = (keyword or "").strip().lower()
        for line in lines:
            m = re.match(
                r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] ([\w.]+): (.*)$",
                line.rstrip("\n"))
            if not m:
                continue
            ts, lv, mod, msg = m.groups()
            if lv == "CRITICAL":
                lv = "ERROR"
            if want != "ALL" and lv != want:
                continue
            if kw and kw not in line.lower():
                continue
            out.append({
                "time": ts[11:],          # 只给手机看时分秒，日期在标题里说明
                "level": lv,
                "module": mod,
                "message": msg,
            })
        return out[-limit:]

    def _log_files(self) -> list:
        files = []
        today = os.path.join(self.log_dir, "app.log")
        if os.path.exists(today):
            files.append(today)
        pat = re.compile(r"^app\.log\.\d{4}-\d{2}-\d{2}$")
        try:
            dated = [os.path.join(self.log_dir, n)
                     for n in os.listdir(self.log_dir) if pat.match(n)]
        except OSError:
            dated = []
        dated.sort(reverse=True)
        return files + dated

    def _read_recent_lines(self, want: int) -> list:
        """从最新文件往前读，凑够 want 行。从尾部取，因为最新的最有价值。"""
        out = []
        for path in self._log_files():
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue
            out = lines + out
            if len(out) >= want:
                return out[-want:]
        return out


class _Handler(BaseHTTPRequestHandler):
    """HTTP 请求处理。通过类属性拿到 Bridge 与令牌（由 server 注入）。"""

    bridge: ControlBridge = None      # type: ignore
    token: str = ""
    server_version = "FrpHelperMobile/1.0"
    protocol_version = "HTTP/1.1"

    # 关掉默认的 stderr 日志（会污染我们的日志文件）
    def log_message(self, fmt, *args):      # noqa: A003
        LOG.debug("手机接口 %s - %s", self.address_string(), fmt % args)

    # ---------------- 鉴权 ----------------
    def _authorized(self) -> bool:
        got = self.headers.get("X-Frp-Token", "")
        return bool(got) and hmac.compare_digest(got, self.token)

    # ---------------- 响应 ----------------
    def _send_json(self, payload, code: int = 200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "X-Frp-Token,Content-Type")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _ok(self, data=None):
        self._send_json({"ok": True, "data": data})

    def _err(self, msg: str, code: int = 400):
        self._send_json({"ok": False, "error": msg}, code)

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return {}
        if n <= 0 or n > 1_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8")) or {}
        except (ValueError, UnicodeDecodeError):
            return {}

    # ---------------- 路由 ----------------
    def do_OPTIONS(self):       # noqa: N802
        self._send_json({"ok": True})

    def do_GET(self):           # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path == "/api/ping":
            # 探测不需要令牌？需要 —— 否则任何人都能扫描到你开了这个口子。
            if not self._authorized():
                return self._err("访问令牌不正确", 401)
            return self._ok("pong")

        if not self._authorized():
            return self._err("访问令牌不正确", 401)

        b = self.bridge
        try:
            if path == "/api/stats":
                return self._ok(b.state())
            if path == "/api/connections":
                return self._ok(b.connections())
            if path == "/api/server-info":
                return self._ok(b.server_info())
            if path == "/api/rules":
                return self._ok(b.rules_payload())
            if path == "/api/logs":
                lv = (query.get("level") or ["ALL"])[0]
                kw = (query.get("keyword") or [""])[0]
                try:
                    lim = int((query.get("limit") or ["400"])[0])
                except ValueError:
                    lim = 400
                return self._ok(b.logs(lv, kw, lim))
        except Exception as exc:            # noqa: BLE001 接口层兜底，绝不 500 崩掉
            LOG.warning("手机接口处理 %s 出错: %s", path, exc)
            return self._err("服务端处理异常：%s" % exc, 500)

        return self._err("未知接口：%s" % path, 404)

    def do_POST(self):          # noqa: N802
        if not self._authorized():
            return self._err("访问令牌不正确", 401)
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        b = self.bridge
        data = self._body()
        try:
            if path == "/api/control":
                which = str(data.get("which", "")).lower()
                action = str(data.get("action", "")).lower()
                if which not in ("server", "client") or action not in ("start", "stop"):
                    return self._err("参数不合法：which=server|client, action=start|stop")
                if b._busy():
                    return self._err("程序正忙，请稍后重试")
                if which == "server":
                    if action == "start":
                        b._start_server()
                        return self._ok("已请求启动服务端")
                    b._stop_server()
                    return self._ok("已请求停止服务端")
                if action == "start":
                    b._start_client()
                    return self._ok("已请求启动客户端")
                b._stop_client()
                return self._ok("已请求停止客户端")

            if path == "/api/rules/add":
                host = str(data.get("host", "*")).strip() or "*"
                ports = str(data.get("ports", "*")).strip() or "*"
                note = str(data.get("note", "")).strip()
                action = str(data.get("action", "deny")).strip().lower()
                b.add_rule(host, ports, note, action)
                LOG.info("手机端新增过滤规则 [%s] %s:%s",
                         "白名单" if action in ("allow", "whitelist") else "黑名单",
                         host, ports)
                return self._ok("规则已添加")

            if path == "/api/rules/remove":
                try:
                    idx = int(data.get("index", -1))
                except (TypeError, ValueError):
                    return self._err("index 必须是整数")
                if b.remove_rule(idx):
                    LOG.info("手机端删除过滤规则 #%d", idx)
                    return self._ok("规则已删除")
                return self._err("规则序号不存在")

            if path == "/api/rules/action":
                try:
                    idx = int(data.get("index", -1))
                except (TypeError, ValueError):
                    return self._err("index 必须是整数")
                action = str(data.get("action", "deny")).strip().lower()
                if b.set_rule_action(idx, action):
                    LOG.info("手机端把规则 #%d 改为%s", idx,
                             "白名单" if action in ("allow", "whitelist") else "黑名单")
                    return self._ok("规则类型已更新")
                return self._err("规则序号不存在")

            if path == "/api/rules/mode":
                mode = str(data.get("mode", "blacklist"))
                enabled = data.get("enabled")
                b.set_rule_mode(mode, enabled)
                LOG.info("手机端切换默认策略：%s enabled=%s", mode, enabled)
                return self._ok("默认策略已更新")
        except Exception as exc:            # noqa: BLE001
            LOG.warning("手机接口处理 %s 出错: %s", path, exc)
            return self._err("服务端处理异常：%s" % exc, 500)

        return self._err("未知接口：%s" % path, 404)


class MobileApiServer:
    """手机控制接口的服务端（后台线程跑，随程序退出自动收尾）。"""

    def __init__(self, host: str, port: int, bridge: ControlBridge):
        self.host = host
        self.port = port
        self.bridge = bridge
        self.token = new_token()
        self._httpd = None
        self._thread = None

    # ---------------- 生命周期 ----------------
    def start(self) -> bool:
        handler = type("_BoundHandler", (_Handler,), {
            "bridge": self.bridge,
            "token": self.token,
        })
        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        except OSError as exc:
            LOG.error("手机控制接口启动失败（%s:%d）：%s", self.host, self.port, exc)
            return False
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="mobile-api", daemon=True)
        self._thread.start()
        real_port = self._httpd.server_address[1]
        LOG.info("=" * 62)
        LOG.info("手机控制接口已开启： http://%s:%d",
                 "127.0.0.1" if self.host in ("0.0.0.0", "") else self.host, real_port)
        LOG.info("访问令牌： %s", self.token)
        LOG.info("在鸿蒙 App「设置」页填入：IP、端口 %d、上面的令牌", real_port)
        if self.host in ("0.0.0.0", ""):
            LOG.warning("注意：接口已监听所有网卡，手机需与电脑在同一局域网。")
            LOG.warning("请勿将该端口暴露到公网。")
        LOG.info("=" * 62)
        return True

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except OSError:
                pass
            self._httpd = None
        LOG.info("手机控制接口已关闭")

    @property
    def running(self) -> bool:
        return self._httpd is not None

    def info(self) -> dict:
        """给界面显示用。"""
        if self._httpd is None:
            return {"running": False}
        port = self._httpd.server_address[1]
        shown = "127.0.0.1" if self.host in ("0.0.0.0", "") else self.host
        return {
            "running": True,
            "url": "http://%s:%d" % (shown, port),
            "token": self.token,
            "token_short": hashlib.sha256(self.token.encode()).hexdigest()[:8],
            "lan": self.host in ("0.0.0.0", ""),
        }
