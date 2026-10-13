"""
test_p2p.py —— P2P 打洞 + 自动回退测试

覆盖用例：
    1. 打洞成功路径      —— 双方能互通时，客户端应报告打洞成功
    2. 打洞失败自动回退  —— 打洞口不可达时，限时放弃，且 TCP 中转仍完全可用
    3. 耗时上限          —— 打洞尝试必须严格限时，不能拖慢主流程
    4. 统计计数          —— 服务端能看到 p2p 尝试/成功计数
    5. 关闭开关          —— --no_p2p 时不应发起打洞

运行： python test_p2p.py
"""

import asyncio
import os
import sys

sys.path.insert(0, ".")

from protocol import get_logger

logger = get_logger("p2p")

HERE = os.path.dirname(os.path.abspath(__file__))
PYEXE = sys.executable
CERT = os.path.join(HERE, "certs")

SERVE_PORT = 19700
TCP_PORT = 19701
LOCAL_PORT = 19702
TOKEN = "p2p-test-token"


LOCAL_SERVICE_CODE = f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")

async def fake(reader, writer):
    await reader.read(4096)
    body = b"P2P-OK"
    writer.write(b"HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s"
                 % (len(body), body))
    await writer.drain()
    writer.close()

async def main():
    s = await asyncio.start_server(fake, "127.0.0.1", {LOCAL_PORT})
    print("READY", flush=True)
    await s.serve_forever()

asyncio.run(main())
"""


def frpc_code(extra: str = "") -> str:
    return f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")
from frpc import Frpc

class Args: pass
a = Args()
a.serve_host, a.serve_port = "127.0.0.1", {SERVE_PORT}
a.local_host, a.local_port = "127.0.0.1", {LOCAL_PORT}
a.proxy_name, a.remote_port = "p2pcli", {TCP_PORT}
a.udp_port = 0
a.token, a.token_file = r"{TOKEN}", ""
a.ca_file, a.insecure, a.no_tls = r"{CERT}/ca.crt", False, False
a.p2p_timeout = 3.0
{extra}
a.log_level = "INFO"

async def main():
    print("READY", flush=True)
    await Frpc(a).start()

asyncio.run(main())
"""


class FrpsArgs:
    pass


def make_frps_args(**over):
    a = FrpsArgs()
    a.serve_host, a.serve_port = "127.0.0.1", SERVE_PORT
    a.user_host = "127.0.0.1"
    a.token = TOKEN
    a.token_file = ""
    a.cert_file = os.path.join(CERT, "server.crt")
    a.key_file = os.path.join(CERT, "server.key")
    a.ca_cert_file = ""
    a.ca_key_file = ""
    a.cert_host = []
    a.cert_renew_days = 30
    a.max_conn_per_ip = 20
    a.max_active_conns = 100
    a.max_queued = 50
    a.udp_target_addr = ""
    a.max_udp_sessions = 512
    a.udp_session_timeout = 60
    a.enable_p2p = True
    a.log_level = "INFO"
    for k, v in over.items():
        setattr(a, k, v)
    return a


def kill(proc) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
    except (ProcessLookupError, OSError):
        pass


async def spawn(code: str, name: str, wait_ready: bool = True):
    proc = await asyncio.create_subprocess_exec(
        PYEXE, "-c", code,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    if wait_ready:
        line = await asyncio.wait_for(proc.stdout.readline(), timeout=20)
        logger.info("[%s] 就绪: %s", name, line.decode(errors="replace").strip())
    return proc


async def wait_for_clients(frps, expect: int, timeout: int = 25) -> bool:
    for _ in range(timeout):
        await asyncio.sleep(1)
        if len(frps.sessions) >= expect:
            return True
    return False


async def probe(tag: str, timeout: float = 8.0) -> bool:
    """走 TLS 请求一次，验证 TCP 中转仍然可用。"""
    import ssl as _ssl
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=os.path.join(CERT, "ca.crt"))
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", TCP_PORT, ssl=ctx), timeout=timeout
        )
        w.write(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
        await w.drain()
        data = await asyncio.wait_for(r.read(65536), timeout=timeout)
        w.close()
        ok = b"P2P-OK" in data
    except Exception as exc:
        logger.warning("[%s] 请求失败: %s", tag, exc)
        ok = False
    logger.info("[%s] %s", tag, "✅ 通" if ok else "❌ 不通")
    return ok


async def main():
    from frps import Frps

    results = {}
    local_proc = await spawn(LOCAL_SERVICE_CODE, "本地服务")
    frpc_proc = None
    frps_task = None

    try:
        # ============ 用例 1：打洞成功 + 中转可用 ============
        logger.info("=" * 60)
        logger.info("用例 1/3/4：打洞尝试（同机可达，应成功）+ 中转仍可用")
        frps = Frps(make_frps_args())
        frps_task = asyncio.create_task(frps.start())
        await asyncio.sleep(2)
        logger.info("  P2P 打洞口端口 = %d", frps.p2p_udp_port)

        t_start = asyncio.get_running_loop().time()
        frpc_proc = await spawn(frpc_code(), "frpc")
        await wait_for_clients(frps, 1)
        # 等打洞完成（连 3 秒超时 + 一点余量）
        await asyncio.sleep(5)
        elapsed = asyncio.get_running_loop().time() - t_start

        st = frps.stats
        logger.info("  服务端统计 | %s", st.summary())
        results["打洞被尝试"] = st.p2p_attempts >= 1
        results["打洞成功(同机可达)"] = st.p2p_success >= 1
        logger.info("  尝试=%d 成功=%d → %s",
                    st.p2p_attempts, st.p2p_success,
                    "✅" if results["打洞被尝试"] else "❌")

        # 中转路径完全不受影响
        results["中转仍可用"] = await probe("打洞后走中转")
        kill(frpc_proc)
        frpc_proc = None

        # ============ 用例 3：打洞耗时上限（单独测打洞本身） ============
        logger.info("=" * 60)
        logger.info("用例 3：打洞尝试本身的耗时必须受限（黑洞端口）")
        from protocol import P2PHolePuncher
        import os as _os
        p = P2PHolePuncher(_os.urandom(16))
        await p.open(0)
        t0 = asyncio.get_running_loop().time()
        ok = await p.attempt("127.0.0.1", 19998, timeout=2.0)   # 黑洞
        dt = asyncio.get_running_loop().time() - t0
        p.close()
        results["打洞严格限时"] = (not ok) and (dt < 3.5)
        logger.info("  黑洞打洞结果=%s 耗时=%.2fs（应 <3.5s）→ %s", ok, dt,
                    "✅" if results["打洞严格限时"] else "❌")

        # ============ 用例 5：--no_p2p ============
        logger.info("=" * 60)
        logger.info("用例 5：--no_p2p 时客户端不应真的发起打洞")
        # ★ 注意：服务端无从得知客户端是否禁用 P2P，所以它**仍会**下发参数、
        #   仍会把 p2p_attempts +1。真正该验证的是"客户端侧没有去探测"——
        #   表现为：没有 p2p_success 增加（客户端没打，自然没有成功回报）。
        before_success = frps.stats.p2p_success
        before_attempts = frps.stats.p2p_attempts
        frpc_proc = await spawn(frpc_code("a.no_p2p = True"), "frpc-noP2P")
        await wait_for_clients(frps, 1, timeout=25)
        await asyncio.sleep(4)
        after_success = frps.stats.p2p_success
        results["no_p2p 不实际探测"] = (after_success == before_success)
        logger.info("  下发参数(尝试计数) %d→%d；实际打洞成功数 %d→%d（应不变）→ %s",
                    before_attempts, frps.stats.p2p_attempts,
                    before_success, after_success,
                    "✅" if results["no_p2p 不实际探测"] else "❌")
        results["no_p2p 仍能中转"] = await probe("no_p2p 走中转")
        kill(frpc_proc)
        frpc_proc = None

        # ============ 用例 2/3：打洞失败必须限时且不影响中转 ============
        logger.info("=" * 60)
        logger.info("用例 2/3：打洞口不可达 → 限时放弃 + 中转不受影响")
        frps_task.cancel()
        await asyncio.gather(frps_task, return_exceptions=True)
        frps_task = None
        await asyncio.sleep(1)

        # 起一个"关了打洞口"的服务端：enable_p2p=False
        frps2 = Frps(make_frps_args(enable_p2p=False))
        frps_task = asyncio.create_task(frps2.start())
        await asyncio.sleep(2)
        logger.info("  打洞口端口 = %d（应为 0 = 未启用）", frps2.p2p_udp_port)
        frpc_proc = await spawn(frpc_code(), "frpc-nop2p-port")
        await wait_for_clients(frps2, 1, timeout=25)
        await asyncio.sleep(2)
        results["禁用时不发参数"] = (frps2.stats.p2p_attempts == 0)
        results["禁用时中转可用"] = await probe("服务端禁用P2P后走中转")
        logger.info("  尝试数=%d（应为0）→ %s", frps2.stats.p2p_attempts,
                    "✅" if results["禁用时不发参数"] else "❌")

        # ============ 用例 2b：参数下发但端口是黑洞 → 限时回退 ============
        logger.info("=" * 60)
        logger.info("用例 2b：下发参数但打不通 → 客户端必须限时回退")
        frps_task.cancel()
        await asyncio.gather(frps_task, return_exceptions=True)
        frps_task = None
        await asyncio.sleep(1)
        # 用 enable_p2p=True 但把 serve_port 指到一个没人监听的 UDP 高位口
        # 无法直接改 p2p 端口（它复用 serve_port），所以这里用一个"假"端口：
        # 起服务端后手工把 p2p_udp_port 改成黑洞端口，再让客户端连新的。
        frps3 = Frps(make_frps_args())
        frps_task = asyncio.create_task(frps3.start())
        await asyncio.sleep(2)
        # 关掉真实打洞口，改成一个黑洞端口 —— 客户端会对着黑洞打，必然超时
        frps3._stop_p2p_listener()
        frps3.p2p_udp_port = 19999     # 没人监听
        t0 = asyncio.get_running_loop().time()
        frpc_proc = await spawn(frpc_code(), "frpc-blackhole")
        await wait_for_clients(frps3, 1, timeout=25)
        await asyncio.sleep(2)
        # 客户端应在此后 ~3 秒内放弃打洞
        await asyncio.sleep(5)
        logger.info("  尝试=%d 成功=%d", frps3.stats.p2p_attempts, frps3.stats.p2p_success)
        results["黑洞打洞失败"] = (frps3.stats.p2p_attempts >= 1
                                  and frps3.stats.p2p_success == 0)
        results["黑洞仍能中转"] = await probe("黑洞打洞后走中转")
        logger.info("  → %s", "✅" if results["黑洞打洞失败"] else "❌")

    finally:
        if frps_task is not None:
            frps_task.cancel()
            await asyncio.gather(frps_task, return_exceptions=True)
        for p in (frpc_proc, local_proc):
            kill(p)

    print()
    logger.info("=" * 60)
    logger.info("测试结果汇总")
    logger.info("=" * 60)
    all_ok = True
    for name, ok in results.items():
        logger.info("  %-22s %s", name, "✅ 通过" if ok else "❌ 失败")
        all_ok = all_ok and ok
    logger.info("=" * 60)
    logger.info("总结论: %s", "✅ 全部通过" if all_ok else "❌ 存在失败项")
    return 0 if all_ok else 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
