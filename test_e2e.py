"""
test_e2e.py —— 全功能端到端测试（TLS + 鉴权 + 限流 + 统计）

用多进程方式跑，避免"同进程内反复启停 asyncio 资源"带来干扰：
    主进程   ：启停 frps、发起各种探测、校验断言
    子进程 A ：内网 Web 服务（模拟要被穿透的 local_port，常驻）
    子进程 B ：frpc 客户端（常驻）

覆盖的用例：
    1. 正常穿透        —— TLS + token 都对，应能拿到内网响应
    2. 连续两次请求    —— 验证隧道可复用、排队正常
    3. 错误 token      —— 客户端应鉴权失败、连不上
    4. 无 TLS 明文连接 —— 服务端启用了 TLS，明文客户端应被拒
    5. 并发限流        —— 把 max_active 调小，超限的应被拒
    6. 统计数字        —— 校验字节数、隧道数、拒绝数等是否合理

运行： python test_e2e.py
"""

import asyncio
import os
import ssl
import sys

sys.path.insert(0, ".")

from protocol import get_logger

logger = get_logger("e2e")

HERE = os.path.dirname(os.path.abspath(__file__))
PYEXE = sys.executable
CERT = os.path.join(HERE, "certs")

SERVE_PORT = 19100
USER_PORT = 19101
LOCAL_PORT = 19102
TOKEN = "test-secret-token-2026"

# ---------------------------------------------------------------- 子进程代码
LOCAL_SERVICE_CODE = f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")

async def fake(reader, writer):
    await reader.read(4096)
    body = b"HELLO-INTRANET"
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


def frpc_code(token: str) -> str:
    return f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")
from frpc import Frpc

class Args: pass
a = Args()
a.serve_host, a.serve_port = "127.0.0.1", {SERVE_PORT}
a.local_host, a.local_port = "127.0.0.1", {LOCAL_PORT}
a.proxy_name, a.remote_port = "single", {USER_PORT}
a.token = r"{token}"
a.token_file = ""
a.ca_file, a.insecure, a.no_tls = r"{CERT}/ca.crt", False, False
a.log_level = "INFO"

async def main():
    print("READY", flush=True)
    await Frpc(a).start()

asyncio.run(main())
"""


def kill(proc) -> None:
    """安全地结束子进程（已经退出时不报错）。"""
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
    a.log_level = "INFO"
    for k, v in over.items():
        setattr(a, k, v)
    return a


async def probe_https(tag, path="/", timeout=8):
    """以外部用户身份（走 TLS）请求一次，返回响应内容或 None。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=os.path.join(CERT, "ca.crt"))
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", USER_PORT, ssl=ctx), timeout=timeout
        )
        writer.write(f"GET {path} HTTP/1.1\r\nHost: t\r\n\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=3)
        ok = b"HELLO-INTRANET" in data
        logger.info("[%s] %s", tag, "✅ 通" if ok else "❌ 响应异常")
        return data if ok else None
    except Exception as exc:
        logger.info("[%s] ❌ 失败: %s", tag, exc)
        return None


async def wait_for_clients(frps, expect: int, timeout: int = 25) -> bool:
    for _ in range(timeout):
        await asyncio.sleep(1)
        if len(frps.sessions) >= expect:
            return True
    return False


async def main():
    from frps import Frps

    results = {}
    local_proc = await spawn(LOCAL_SERVICE_CODE, "本地服务")
    frpc_proc = None
    bad_proc = None
    frps_task = None
    frps_task2 = None

    try:
        # ============ 用例 1 & 2：验证穿透 ============
        logger.info("=" * 60)
        logger.info("用例 1/2：正常穿透（TLS + 正确 token）")
        frps = Frps(make_frps_args())
        frps_task = asyncio.create_task(frps.start())
        await asyncio.sleep(2)
        frpc_proc = await spawn(frpc_code(TOKEN), "frpc")
        await wait_for_clients(frps, 1)
        await asyncio.sleep(1)

        r1 = await probe_https("第一次请求")
        r2 = await probe_https("第二次请求", "/again")
        results["正常穿透"] = bool(r1 and r2)

        # ============ 用例 6：统计校验 ============
        await asyncio.sleep(0.5)
        st = frps.stats
        logger.info("服务端统计 | %s", st.summary())
        results["统计-隧道数"] = st.tunnels_established >= 2
        results["统计-转发字节"] = st.bytes_forwarded > 0
        results["统计-连接计数"] = st.connections_accepted >= 2

        # ============ 用例 3：错误 token 应被拒 ============
        logger.info("=" * 60)
        logger.info("用例 3：错误 token 应鉴权失败")
        before = frps.stats.auth_failures
        bad_proc = await spawn(frpc_code("WRONG-TOKEN"), "frpc-坏token", wait_ready=False)
        await asyncio.sleep(4)
        results["错误token被拒"] = frps.stats.auth_failures > before
        logger.info("[错误token] 鉴权失败 %d → %d → %s", before, frps.stats.auth_failures,
                    "✅" if results["错误token被拒"] else "❌")
        kill(bad_proc)

        # ============ 用例 4：明文连接应被拒 ============
        logger.info("=" * 60)
        logger.info("用例 4：明文连接应被 TLS 拒绝")
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", USER_PORT), timeout=5
            )
            w.write(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
            await w.drain()
            data = await asyncio.wait_for(r.read(1024), timeout=5)
            leaked = b"HELLO-INTRANET" in data
            results["明文被拒"] = not leaked
            logger.info("[明文] 收到 %d 字节，泄露内网内容=%s → %s",
                        len(data), leaked, "✅ 已拒绝" if not leaked else "❌ 有泄露")
            w.close()
        except Exception as exc:
            results["明文被拒"] = True
            logger.info("[明文] 连接被拒: %s → ✅", type(exc).__name__)

        # ============ 用例 5：并发限流 ============
        logger.info("=" * 60)
        logger.info("用例 5：并发限流（max_active_conns = 1）")
        frps_task.cancel()
        await asyncio.gather(frps_task, return_exceptions=True)
        frps_task = None
        await asyncio.sleep(1)

        frps2 = Frps(make_frps_args(max_active_conns=1))
        frps_task2 = asyncio.create_task(frps2.start())
        logger.info("[限流] 等待 frpc 重连到新的服务端……")
        if not await wait_for_clients(frps2, 1, timeout=30):
            logger.error("[限流] frpc 未能重连，该用例作废")
        await asyncio.sleep(1)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=os.path.join(CERT, "ca.crt"))

        async def one_probe(i):
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", USER_PORT, ssl=ctx), timeout=5
                )
                w.write(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
                await w.drain()
                data = await asyncio.wait_for(r.read(65536), timeout=6)
                w.close()
                return b"HELLO-INTRANET" in data
            except Exception:
                return False

        outcomes = await asyncio.gather(*[one_probe(i) for i in range(6)])
        served = sum(1 for o in outcomes if o)
        logger.info("[限流] 6 个并发请求，成功 %d 个，被限流 %d 个", served, 6 - served)
        logger.info("[限流] 服务端统计 | %s", frps2.stats.summary())
        results["并发限流"] = (served >= 1) and (frps2.stats.rejected_overload > 0)
    finally:
        for t in (frps_task, frps_task2):
            if t is not None:
                t.cancel()
                await asyncio.gather(t, return_exceptions=True)
        for p in (frpc_proc, local_proc, bad_proc):
            kill(p)

    # ============ 汇总 ============
    print()
    logger.info("=" * 60)
    logger.info("测试结果汇总")
    logger.info("=" * 60)
    all_ok = True
    for name, ok in results.items():
        logger.info("  %-16s %s", name, "✅ 通过" if ok else "❌ 失败")
        all_ok = all_ok and ok
    logger.info("=" * 60)
    logger.info("总结论: %s", "✅ 全部通过" if all_ok else "❌ 存在失败项")
    return 0 if all_ok else 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
