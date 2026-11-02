# -*- coding: utf-8 -*-
"""
端到端验证：复现线上那个"证书里没有公网 IP"的故障，并验证修复有效。

设计思路
    frp 客户端连服务端用的是 serve_host。本机的局域网地址（如 192.168.3.x）
    与服务端证书里的 127.0.0.1 不同，正好等价于线上"公网 IP vs 证书里只有
    localhost"的关系 —— 故障条件可以在一台机器上完整复现，不用真的上云。

四个场景
    A 修复前行为：证书无该地址 + 严格校验  → 必须失败（复现 BUG）
    B 修复后行为：证书无该地址 + 不校验主机名 → 必须成功（能用）
    C 重签逻辑：ensure_certs 补上该地址，且 CA 指纹不变 → 客户端不用换 ca.crt
    D 严格模式：证书补齐地址后 + 严格校验 → 必须成功（最规范的终态）

运行：  py -3 test_fix_e2e.py
"""
import asyncio
import hashlib
import os
import socket
import sys
import tempfile
from types import SimpleNamespace as NS

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gui          # noqa: E402
import gen_cert     # noqa: E402
import frps         # noqa: E402,F401  （确保模块可用）
import frpc         # noqa: E402,F401


def lan_ip() -> str:
    """取本机对外地址（不会真的发包）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("223.5.5.5", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def sha16(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


async def echo_server(port: int):
    async def _echo(reader, writer):
        try:
            data = await reader.read(64)
            writer.write(b"ECHO:" + data)
            await writer.drain()
        finally:
            writer.close()
    return await asyncio.start_server(_echo, "127.0.0.1", port)


async def start_server(cert_dir, log_path, serve_port, cert_hosts):
    args = NS(
        serve_host="0.0.0.0", serve_port=serve_port, user_host="0.0.0.0",
        token="", token_file=log_path,
        cert_file=os.path.join(cert_dir, "server.crt"),
        key_file=os.path.join(cert_dir, "server.key"),
        ca_cert_file=os.path.join(cert_dir, "ca.crt"),
        ca_key_file=os.path.join(cert_dir, "ca.key"),
        cert_host=cert_hosts, cert_renew_days=30,
        max_conn_per_ip=20, max_active_conns=100, max_queued=50,
        udp_target_addr="", max_udp_sessions=512, udp_session_timeout=60,
        enable_p2p=False, log_level="INFO",
    )
    holder = {}
    task = asyncio.create_task(gui._run_server(args, holder))
    await asyncio.sleep(0.7)
    return task, holder


async def start_client(cert_dir, token_path, serve_host, serve_port,
                       local_port, remote_port, verify_hostname, name):
    args = NS(
        serve_host=serve_host, serve_port=serve_port,
        local_host="127.0.0.1", local_port=local_port,
        proxy_name=name, remote_port=remote_port,
        udp_port=0, udp_local_port=0, p2p_timeout=3.0, enable_p2p=False,
        token="", token_file=token_path,
        ca_file=os.path.join(cert_dir, "ca.crt"),
        insecure=False, no_tls=False,
        no_verify_hostname=not verify_hostname,
        log_level="INFO",
    )
    holder = {}
    task = asyncio.create_task(gui._run_client(args, holder))
    return task, holder


async def wait_registered(holder, seconds=8.0) -> bool:
    """等服务端登记到客户端（sessions 以 proxy_name 为键）。

    ★ 不能拿 start_server 返回时的引用：那一刻 Frps 对象可能还在构造中。
      每轮都从 holder 里重新取，才是"当前活着的那个服务端"。
    """
    for _ in range(int(seconds * 10)):
        srv = holder.get("obj")
        if srv is not None and getattr(srv, "sessions", None):
            return True
        await asyncio.sleep(0.1)
    srv = holder.get("obj")
    print("    [诊断] holder.obj=%r (%s)  sessions=%r"
          % (type(srv).__name__, "None" if srv is None else "ok",
             None if srv is None else getattr(srv, "sessions", "<无此属性>")))
    return False


async def probe_forward(cert_dir, remote_port, timeout=12.0) -> bool:
    """真正的端到端证据：从外部连服务端的用户端口，走完隧道拿到回声。

    仅仅"注册成功"说明不了转发是否正常，必须真的收发了字节才算通。

    ★ 这里必须用**明文 TCP** 连接，不能用 TLS。
      用户端口的对端是 mstsc、浏览器这类普通客户端，它们只会按自己的协议
      直接发包，不会先做 TLS 握手。如果测试用 TLS 去连，就会掩盖掉
      "端口套了 TLS 导致真实客户端连不上"这类故障 —— 而那正是线上症状。
      换句话说：这一步要用和用户完全一样的方式连接，测出来的结论才算数。
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", remote_port),
                timeout=4)
            writer.write(b"hello-frp")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(64), timeout=5)
            writer.close()
            if resp == b"ECHO:hello-frp":
                return True
        except (OSError, asyncio.TimeoutError, ConnectionError):
            pass
        await asyncio.sleep(0.3)
    return False


async def stop(*tasks):
    for t in tasks:
        if t is not None:
            t.cancel()
    for t in tasks:
        if t is not None:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass


async def main():
    ip = lan_ip()

    def log(fmt, *a):
        print("    " + (fmt % a if a else fmt))

    print("=" * 70)
    print("本机局域网地址（模拟线上的公网 IP）：%s" % ip)
    print("=" * 70)

    tmp = tempfile.mkdtemp(prefix="frp-fixtest-")
    cert_dir = os.path.join(tmp, "certs")
    token_path = os.path.join(tmp, "tokens.txt")
    gui.ensure_token(token_path, log=log)
    results = []

    # ---------- 场景 A：证书里没有该地址 + 严格校验 ----------
    print("\n【场景 A】证书 SAN 仅 localhost/127.0.0.1，客户端严格校验 → 应失败")
    gui.generate_certs(cert_dir, hosts=["localhost", "127.0.0.1"],
                       reuse_ca=False, log=log)
    print("  证书 SAN :", gen_cert.cert_san_hosts(os.path.join(cert_dir, "server.crt")))
    echo_a = await echo_server(19991)
    st, sh = await start_server(cert_dir, token_path, 19880, ["localhost"])
    ct, ch = await start_client(cert_dir, token_path, ip, 19880, 19991, 19001,
                                True, "caseA")
    ok_a = await wait_registered(sh, 7)
    await stop(ct, st)
    echo_a.close()
    print("  → 结果：%s（符合预期：失败）" % ("连上了" if ok_a else "握手被拒"))
    results.append(("A 复现故障：严格校验 + 证书无该地址 → 失败", ok_a is False))

    # ---------- 场景 B：同一套证书 + 不校验主机名 ----------
    print("\n【场景 B】同一套证书，客户端关闭主机名校验 → 应成功")
    echo_b = await echo_server(19992)
    st, sh = await start_server(cert_dir, token_path, 19881, ["localhost"])
    ct, ch = await start_client(cert_dir, token_path, ip, 19881, 19992, 19002,
                                False, "caseB")
    ok_b = await wait_registered(sh, 9)
    fwd_b = await probe_forward(cert_dir, 19002) if ok_b else False
    await stop(ct, st)
    echo_b.close()
    print("  → 注册：%s / 实际转发：%s（符合预期：都成功）"
          % ("成功" if ok_b else "失败", "通" if fwd_b else "不通"))
    results.append(("B 修复生效：仅校验 CA、不校验主机名 → 注册成功", ok_b is True))
    results.append(("B 数据可通：隧道内真实收发字节", fwd_b is True))

    # ---------- 场景 C：ensure_certs 自动补签 SAN，CA 不变 ----------
    print("\n【场景 C】调用 ensure_certs 补上 %s → SAN 应包含它，且 CA 指纹不变" % ip)
    ca_before = sha16(os.path.join(cert_dir, "ca.crt"))
    ok_c = gui.ensure_certs([ip], cert_dir, log=log)
    san_after = gen_cert.cert_san_hosts(os.path.join(cert_dir, "server.crt"))
    ca_after = sha16(os.path.join(cert_dir, "ca.crt"))
    print("  重签后 SAN :", san_after)
    print("  CA 指纹    : %s → %s" % (ca_before, ca_after))
    results.append(("C 自动补签：SAN 覆盖新地址", ok_c and ip in san_after))
    results.append(("C 复用 CA：客户端无需更换 ca.crt", ca_before == ca_after))

    # ---------- 场景 D：补齐地址后，严格模式应当成功 ----------
    print("\n【场景 D】证书已含 %s，客户端严格校验 → 应成功（最规范终态）" % ip)
    echo_d = await echo_server(19993)
    st, sh = await start_server(cert_dir, token_path, 19882, [ip, "localhost"])
    ct, ch = await start_client(cert_dir, token_path, ip, 19882, 19993, 19003,
                                True, "caseD")
    ok_d = await wait_registered(sh, 9)
    fwd_d = await probe_forward(cert_dir, 19003) if ok_d else False
    await stop(ct, st)
    echo_d.close()
    print("  → 注册：%s / 实际转发：%s（符合预期：都成功）"
          % ("成功" if ok_d else "失败", "通" if fwd_d else "不通"))
    results.append(("D 严格模式可用：证书补齐地址后无需放宽校验", ok_d is True))
    results.append(("D 数据可通：严格模式下真实收发字节", fwd_d is True))

    # ---------- 汇总 ----------
    print("\n" + "=" * 70)
    all_ok = True
    for name, ok in results:
        print("  %s  %s" % ("PASS" if ok else "FAIL", name))
        all_ok = all_ok and ok
    print("=" * 70)
    print("RESULT: %s" % ("PASS" if all_ok else "FAIL"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
