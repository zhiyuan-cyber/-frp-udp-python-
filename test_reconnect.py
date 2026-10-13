"""
test_reconnect.py —— 验证「服务端重启后，客户端能自愈重连」

在 TLS + token 鉴权全开的前提下测试，比纯明文场景更接近真实部署。

流程：
    1) 起 frps + frpc + 内网服务，确认第一次穿透成功
    2) 关掉 frps（模拟服务端宕机/重启）
    3) 确认此时不通
    4) 重新拉起 frps
    5) 等客户端自动重连，再探测，确认穿透恢复

用多进程跑，避免"同进程内反复启停 asyncio 资源"带来干扰。

运行： python test_reconnect.py
"""

import asyncio
import os
import ssl
import sys

sys.path.insert(0, ".")

from protocol import get_logger

logger = get_logger("e2e-reconnect")

HERE = os.path.dirname(os.path.abspath(__file__))
PYEXE = sys.executable
CERT = os.path.join(HERE, "certs")

SERVE_PORT = 19200
USER_PORT = 19201
LOCAL_PORT = 19202
TOKEN = "reconnect-test-token"
PROXY_NAME = "reconn"

LOCAL_SERVICE_CODE = f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")

async def fake(reader, writer):
    await reader.read(4096)
    body = b"PONG"
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

FRPC_CODE = f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")
from frpc import Frpc

class Args: pass
a = Args()
a.serve_host, a.serve_port = "127.0.0.1", {SERVE_PORT}
a.local_host, a.local_port = "127.0.0.1", {LOCAL_PORT}
a.proxy_name, a.remote_port = "{PROXY_NAME}", {USER_PORT}
a.token = r"{TOKEN}"
a.token_file = ""
a.ca_file, a.insecure, a.no_tls = r"{CERT}/ca.crt", False, False
a.log_level = "INFO"

async def main():
    print("READY", flush=True)
    await Frpc(a).start()

asyncio.run(main())
"""


class FrpsArgs:
    pass


def make_frps_args():
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
    return a


async def spawn(code: str, name: str):
    proc = await asyncio.create_subprocess_exec(
        PYEXE, "-c", code,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    line = await asyncio.wait_for(proc.stdout.readline(), timeout=20)
    logger.info("[%s] 就绪: %s", name, line.decode(errors="replace").strip())
    return proc


def kill(proc) -> None:
    """安全地结束子进程（已经退出时不报错）。"""
    if proc is None:
        return
    try:
        proc.terminate()
    except (ProcessLookupError, OSError):
        pass


async def probe(tag: str) -> bool:
    """以外部用户身份走 TLS 请求一次，返回是否通。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=os.path.join(CERT, "ca.crt"))
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", USER_PORT, ssl=ctx), timeout=6
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), timeout=6)
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=3)
        ok = b"PONG" in data
    except Exception as exc:
        logger.warning("[%s] 请求失败: %s", tag, exc)
        ok = False
    logger.info("[%s] %s", tag, "✅ 通" if ok else "❌ 不通")
    return ok


async def wait_for_clients(frps, expect: int, timeout: int = 30) -> bool:
    """轮询等待指定数量的客户端注册上来。"""
    for _ in range(timeout):
        await asyncio.sleep(1)
        if len(frps.sessions) >= expect:
            return True
    return False


async def main():
    from frps import Frps

    local_proc = await spawn(LOCAL_SERVICE_CODE, "本地服务")
    frpc_proc = await spawn(FRPC_CODE, "frpc")
    frps_task = None
    frps_task2 = None

    try:
        # --- frps 第 1 次启动 ---
        logger.info(">>> 启动服务端（第 1 次）")
        frps1 = Frps(make_frps_args())
        frps_task = asyncio.create_task(frps1.start())
        if not await wait_for_clients(frps1, 1):
            logger.error("客户端未能首次接入，测试作废")
        await asyncio.sleep(1)
        r1 = await probe("重启前")

        # --- 关掉 frps，模拟服务端宕机 ---
        logger.info(">>> 关闭服务端（模拟宕机）")
        frps_task.cancel()
        await asyncio.gather(frps_task, return_exceptions=True)
        frps_task = None
        await asyncio.sleep(1.5)
        r2 = await probe("服务端已关")

        # --- 重新拉起 frps ---
        logger.info(">>> 重启服务端（第 2 次）")
        frps2 = Frps(make_frps_args())
        frps_task2 = asyncio.create_task(frps2.start())
        logger.info(">>> 等待客户端自动重连……")
        reconnected = await wait_for_clients(frps2, 1, timeout=30)
        await asyncio.sleep(1)
        r3 = await probe("重启后") if reconnected else False
        if not reconnected:
            logger.warning("客户端在 30 秒内没有自动重连回来")
    finally:
        for t in (frps_task, frps_task2):
            if t is not None:
                t.cancel()
                await asyncio.gather(t, return_exceptions=True)
        kill(frpc_proc)
        kill(local_proc)

    print()
    logger.info("重启前=%s | 服务端关闭=%s(预期不通) | 重启后=%s", r1, r2, r3)
    passed = r1 and (not r2) and r3
    logger.info("自愈能力验证: %s", "✅ 通过" if passed else "❌ 未达预期")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
