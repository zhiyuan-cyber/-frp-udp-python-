"""test_mobile_api.py —— 验证手机控制接口（鸿蒙 App 的后端）

覆盖：鉴权、状态/连接/日志/规则各接口、启停回调、日志过滤、端口顺延。
不依赖 GUI —— 用假 Bridge 替代，测的是真正的 HTTP 传输层。
"""
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mobile_api
import rules as rules_mod

FAILS = []


def check(cond, desc):
    print("  [%s] %s" % ("OK" if cond else "FAIL", desc))
    if not cond:
        FAILS.append(desc)


def call(port, token, path, method="GET", body=None):
    url = "http://127.0.0.1:%d%s" % (port, path)
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("X-Frp-Token", token)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="frp_mobile_")
    rules_file = os.path.join(tmp, "rules.json")
    log_dir = os.path.join(tmp, "logs")
    os.makedirs(log_dir, exist_ok=True)

    # 造一份日志（含 4 个级别 + 多模块）
    with open(os.path.join(log_dir, "app.log"), "w", encoding="utf-8") as f:
        f.write("2026-10-14 15:46:16 [INFO] gui: 界面已就绪\n")
        f.write("2026-10-14 15:46:17 [INFO] frps: 控制端口监听 0.0.0.0:8800\n")
        f.write("2026-10-14 15:46:18 [WARNING] frpc: 转发被过滤规则拒绝 192.168.1.5:3389\n")
        f.write("2026-10-14 15:46:19 [ERROR] frp.protocol: 连接中断: timeout\n")
        f.write("2026-10-14 15:46:20 [DEBUG] frp.cert: 证书剩余 824.2 天\n")
        f.write("2026-10-14 15:46:21 [INFO] tray: 托盘图标已添加\n")

    # 造规则
    rs = rules_mod.RuleSet()
    rs.add("*", "3389", "远程桌面")
    rs.add("192.168.*", "5432", "PostgreSQL")
    rs.save(rules_file)

    # 启停回调：记录被调用的动作
    calls = []

    bridge = mobile_api.ControlBridge(
        rules=rs, rules_file=rules_file, log_dir=log_dir, data_dir=tmp,
        start_server=lambda: calls.append("start_server"),
        stop_server=lambda: calls.append("stop_server"),
        start_client=lambda: calls.append("start_client"),
        stop_client=lambda: calls.append("stop_client"),
        stats_provider=lambda: {
            "uptime": 3661, "connections_active": 3, "connections_peak": 7,
            "tunnels_established": 5, "bytes_up": 3_932_160, "bytes_down": 1_048_576,
            "auth_failures": 1, "rejected_overload": 2, "rejected_timeout": 0,
            "rejected_offline": 1, "_role": "server", "_running": True,
            "_speed_up": 2048.0, "_speed_down": 512.0,
        },
        links_provider=lambda: [{
            "proxy": "web", "peer": "203.0.113.9:51234", "target": "127.0.0.1:8080",
            "bytes_up": 1024, "bytes_down": 2048, "elapsed": 125.0,
            "started": time.time() - 125, "p2p": False,
        }],
        info_provider=lambda: {"public_ip": "1.2.3.4", "geo": "江苏 南京",
                               "isp": "电信", "latency": 18},
        busy_provider=lambda: False,
    )

    srv = mobile_api.MobileApiServer("127.0.0.1", 0, bridge)
    print("启动手机接口：", end="")
    ok = srv.start()
    check(ok, "接口启动成功")
    if not ok:
        return 1
    port = srv.info()["url"].rsplit(":", 1)[1]
    port = int(port)
    token = srv.token
    print("  端口 = %d，令牌 = %s" % (port, token))

    print("\n--- 鉴权 ---")
    code, body = call(port, "", "/api/stats")
    check(code == 401, "无令牌被拒（401），实际 %d" % code)
    code, body = call(port, "wrong-token", "/api/stats")
    check(code == 401, "错误令牌被拒（401），实际 %d" % code)
    code, body = call(port, token, "/api/ping")
    check(code == 200 and body.get("ok") and body.get("data") == "pong",
          "正确令牌 ping 通过")

    print("\n--- 状态 ---")
    code, body = call(port, token, "/api/stats")
    d = body.get("data", {})
    check(d.get("role") == "server" and d.get("running") is True, "角色=server、running=True")
    check(d.get("uptime") == 3661, "运行时长透传（3661）")
    check(d.get("connections") == 3 and d.get("connectionsPeak") == 7, "连接数与峰值")
    check(d.get("bytesUp") == 3_932_160, "累计上行字节")
    check(d.get("speedUp") == 2048.0, "实时上行速度")
    check(d.get("rejected") == 3, "拒绝数合并（2+0+1=3）")
    check(d.get("authFailed") == 1, "鉴权失败数")

    print("\n--- 连接列表 ---")
    code, body = call(port, token, "/api/connections")
    links = body.get("data", [])
    check(len(links) == 1, "返回 1 条连接")
    lk = links[0]
    check(lk["name"] == "web" and lk["bytesUp"] == 1024, "字段名与鸿蒙端对齐（name/bytesUp）")
    check(lk["duration"] == 125.0, "时长字段")
    check("target" in lk and "peer" in lk, "含来源与目标")

    print("\n--- 服务器信息 ---")
    code, body = call(port, token, "/api/server-info")
    si = body.get("data", {})
    check(si.get("publicIp") == "1.2.3.4", "公网 IP")
    check(si.get("geo") == "江苏 南京", "归属地")
    check(si.get("latencyMs") == 18, "延迟")

    print("\n--- 日志 ---")
    code, body = call(port, token, "/api/logs?level=ALL&limit=100")
    logs = body.get("data", [])
    check(len(logs) == 6, "全部日志 6 条，实际 %d" % len(logs))
    mods = {x["module"] for x in logs}
    check(mods == {"gui", "frps", "frpc", "frp.protocol", "frp.cert", "tray"},
          "6 个模块都被解析出来")
    check(logs[0]["time"] == "15:46:16", "时间只给时分秒")

    code, body = call(port, token, "/api/logs?level=WARNING&limit=100")
    logs = body.get("data", [])
    check(len(logs) == 1 and logs[0]["level"] == "WARNING", "按级别筛选（WARNING 1 条）")

    code, body = call(port, token, "/api/logs?level=ALL&keyword=%E8%BD%AC%E5%8F%91&limit=100")
    logs = body.get("data", [])
    check(len(logs) == 1, "按关键字『转发』筛选（1 条）")

    code, body = call(port, token, "/api/logs?level=ERROR&limit=100")
    logs = body.get("data", [])
    check(len(logs) == 1 and logs[0]["level"] == "ERROR", "ERROR 筛选")

    print("\n--- 规则 ---")
    code, body = call(port, token, "/api/rules")
    rp = body.get("data", {})
    check(rp.get("mode") == "blacklist", "黑名单模式映射正确（blocklist→blacklist）")
    check(len(rp.get("rules", [])) == 2, "2 条规则")
    check(rp["rules"][0]["ports"] == "3389", "端口字段名 ports")
    check(rp["rules"][0]["action"] == "deny", "每条规则带自己的 action（deny）")
    check(rp["rules"][0]["enabled"] is True, "每条规则带 enabled")

    code, body = call(port, token, "/api/rules/add", "POST",
                      {"host": "*", "ports": "6379", "note": "Redis"})
    check(code == 200 and body.get("ok"), "新增规则成功")
    check(len(rs.rules) == 3, "内存里变成 3 条")
    check(rs.rules[2].action == "deny", "不指定 action 时默认黑名单")
    check(os.path.exists(rules_file), "规则已落盘")

    # 手机端明确要一条白名单
    code, body = call(port, token, "/api/rules/add", "POST",
                      {"host": "*", "ports": "8080", "note": "我的网站",
                       "action": "allow"})
    check(code == 200 and len(rs.rules) == 4, "指定 action=allow 新增成功")
    check(rs.rules[3].action == "allow", "这条确实是白名单")

    # 改某条规则的类型 —— 手机端也能把黑名单改成白名单
    code, body = call(port, token, "/api/rules/action", "POST",
                      {"index": 0, "action": "allow"})
    check(code == 200 and rs.rules[0].action == "allow", "改类型：黑名单→白名单")
    check(rs.check("127.0.0.1", 3389)[0] is True,
          "改完立即生效：3389 从拒绝变成放行")
    code, body = call(port, token, "/api/rules/action", "POST",
                      {"index": 0, "action": "deny"})
    check(rs.rules[0].action == "deny", "改类型：白名单→黑名单")
    check(rs.check("127.0.0.1", 3389)[0] is False, "改完立即生效：又变回拒绝")
    code, body = call(port, token, "/api/rules/action", "POST",
                      {"index": 99, "action": "deny"})
    check(code == 400, "越界序号被拒（400）")

    # 黑白混排时，接口要把两种类型分别报出来
    code, body = call(port, token, "/api/rules")
    acts = [r["action"] for r in body.get("data", {}).get("rules", [])]
    check(acts == ["deny", "deny", "deny", "allow"],
          "黑白混排时逐条报告类型：%s" % acts)

    code, body = call(port, token, "/api/rules/remove", "POST", {"index": 3})
    check(code == 200 and len(rs.rules) == 3, "删除规则成功")
    code, body = call(port, token, "/api/rules/remove", "POST", {"index": 2})
    check(code == 200 and len(rs.rules) == 2, "再删一条回到 2 条")

    code, body = call(port, token, "/api/rules/mode", "POST",
                      {"mode": "whitelist", "enabled": False})
    check(code == 200 and rs.mode == "allowlist" and rs.enabled is False,
          "切换默认策略为白名单 + 停用规则")

    print("\n--- 启停 ---")
    calls.clear()
    code, body = call(port, token, "/api/control", "POST",
                      {"which": "server", "action": "start"})
    check(code == 200 and calls == ["start_server"], "启动服务端回调被触发")
    calls.clear()
    call(port, token, "/api/control", "POST", {"which": "client", "action": "stop"})
    check(calls == ["stop_client"], "停止客户端回调被触发")
    code, body = call(port, token, "/api/control", "POST",
                      {"which": "bad", "action": "start"})
    check(code == 400, "非法 which 被拒（400）")

    print("\n--- 边界 ---")
    code, body = call(port, token, "/api/nope")
    check(code == 404, "未知路径返回 404")
    # limit 上限
    code, body = call(port, token, "/api/logs?level=ALL&limit=999999")
    check(code == 200, "超大 limit 不报错（内部截断）")

    srv.stop()
    check(not srv.running, "接口已停止")

    print("\n%s（%d 项失败）" % ("全部通过" if not FAILS else "存在失败", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
