"""
test_udp.py —— UDP 转发端到端测试

思路：内网起一个 UDP 回声服务（把收到的内容原样回送），经过
frpc → frps 的 UDP 转发链，外部用 UDP 客户端发请求，应当收到回声。

覆盖用例：
    1. 单路 UDP 回声         —— 基本通路
    2. 连续多个数据报        —— 会话复用（同一来源地址应复用同一会话）
    3. 不同来源地址独立会话  —— 两个 socket 各自一路会话，回包不串台
    4. 大包 / 小包           —— 1 字节 与 1000 字节都要正确
    5. 会话统计              —— frps 统计里能看到 UDP 会话与数据报计数
    6. 会话超时回收          —— 短超时下，空闲会话应被回收

运行： python test_udp.py
"""

import asyncio
import os
import sys

sys.path.insert(0, ".")

from protocol import get_logger

logger = get_logger("udp")

HERE = os.path.dirname(os.path.abspath(__file__))
PYEXE = sys.executable
CERT = os.path.join(HERE, "certs")

SERVE_PORT = 19500
TCP_PORT = 19501        # 客户端仍要声明一个 TCP 端口（协议要求）
UDP_PORT = 19502        # 服务端对外 UDP 端口
LOCAL_TCP = 19503       # 本机 TCP 服务（随便起一个，UDP 测试不用）
LOCAL_UDP = 19504       # 本机 UDP 回声服务
TOKEN = "udp-test-token"


# ---------------------------------------------------------------- 子进程代码
LOCAL_SERVICE_CODE = f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")

async def tcp_handler(reader, writer):
    await reader.read(4096)
    writer.write(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nOK")
    await writer.drain()
    writer.close()

class EchoProto(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)   # 原样回送

async def main():
    await asyncio.start_server(tcp_handler, "127.0.0.1", {LOCAL_TCP})
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        EchoProto, local_addr=("127.0.0.1", {LOCAL_UDP})
    )
    print("READY", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
"""


FRPC_CODE = f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")
from frpc import Frpc

class Args: pass
a = Args()
a.serve_host, a.serve_port = "127.0.0.1", {SERVE_PORT}
a.local_host, a.local_port = "127.0.0.1", {LOCAL_TCP}
a.udp_local_port = {LOCAL_UDP}
a.proxy_name, a.remote_port = "udptest", {TCP_PORT}
a.udp_port = {UDP_PORT}
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
        if len(frps.sessions) >= expect and frps.udp_tunnels:
            return True
    return False


class UdpEcho:
    """一个简单的 UDP 请求-应答客户端，支持复用同一个本地端口。"""

    def __init__(self):
        self.transport = None
        self.reply_queue: asyncio.Queue = asyncio.Queue()

    async def open(self):
        loop = asyncio.get_running_loop()
        q = self.reply_queue

        class Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                q.put_nowait(data)

        self.transport, _ = await loop.create_datagram_endpoint(
            Proto, remote_addr=("127.0.0.1", UDP_PORT)
        )
        return self

    async def request(self, payload: bytes, timeout: float = 5.0):
        self.transport.sendto(payload)
        try:
            return await asyncio.wait_for(self.reply_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def close(self):
        if self.transport:
            self.transport.close()


async def main():
    from frps import Frps

    results = {}
    local_proc = await spawn(LOCAL_SERVICE_CODE, "本地服务")
    frpc_proc = None
    frps_task = None

    try:
        frps = Frps(make_frps_args())
        frps_task = asyncio.create_task(frps.start())
        await asyncio.sleep(2)

        frpc_proc = await spawn(FRPC_CODE, "frpc")
        if not await wait_for_clients(frps, 1):
            logger.error("客户端未能接入（TCP 或 UDP 隧道未就绪）")
        await asyncio.sleep(1)

        # ---------- 用例 1 & 2：单路回声 + 会话复用 ----------
        logger.info("=" * 60)
        logger.info("用例 1/2：UDP 回声 + 会话复用")
        client = await UdpEcho().open()
        r1 = await client.request(b"hello-udp")
        r2 = await client.request(b"second-packet")
        results["UDP回声"] = (r1 == b"hello-udp")
        results["会话复用"] = (r2 == b"second-packet")
        logger.info("  回声1=%r 回声2=%r → %s", r1, r2,
                    "✅" if results["UDP回声"] and results["会话复用"] else "❌")
        sessions_after = frps.stats.udp_sessions_opened
        results["单来源只开1路会话"] = (sessions_after == 1)
        logger.info("  已打开 UDP 会话数 = %d（同一来源两次请求应为 1）→ %s",
                    sessions_after, "✅" if sessions_after == 1 else "❌")

        # ---------- 用例 4：不同长度 ----------
        logger.info("=" * 60)
        logger.info("用例 4：1 字节 与 1000 字节")
        r_small = await client.request(b"x")
        big = b"B" * 1000
        r_big = await client.request(big)
        results["小包"] = (r_small == b"x")
        results["大包"] = (r_big == big)
        logger.info("  小包=%r 大包=%d字节 → %s", r_small, len(r_big or b""),
                    "✅" if results["小包"] and results["大包"] else "❌")

        # ---------- 用例 3：不同来源地址 → 独立会话 ----------
        logger.info("=" * 60)
        logger.info("用例 3：两个不同来源地址应各占一路会话")
        client2 = await UdpEcho().open()
        ra = await client.request(b"from-A")
        rb = await client2.request(b"from-B")
        results["多来源独立"] = (ra == b"from-A" and rb == b"from-B")
        results["两个独立会话"] = (frps.stats.udp_sessions_opened >= 2)
        logger.info("  A=%r B=%r 会话数=%d → %s", ra, rb,
                    frps.stats.udp_sessions_opened,
                    "✅" if results["多来源独立"] else "❌")

        # ---------- 用例 5：统计 ----------
        logger.info("=" * 60)
        logger.info("用例 5：统计校验")
        st = frps.stats
        logger.info("  服务端统计 | %s", st.summary())
        results["统计-数据报数"] = st.udp_datagrams > 0
        results["统计-字节数"] = st.udp_bytes > 0
        logger.info("  UDP 数据报=%d 字节=%d → %s", st.udp_datagrams, st.udp_bytes,
                    "✅" if results["统计-数据报数"] and results["统计-字节数"] else "❌")

        client.close()
        client2.close()

        # ---------- 用例 6：会话超时回收 ----------
        logger.info("=" * 60)
        logger.info("用例 6：会话空闲超时回收")
        # ★ 说明：回收器在监听口建立时读取一次 udp_session_timeout（避免每次循环读配置），
        #   所以不能用"运行中改 args"来验证 —— 必须让服务端**从一开始**就用短超时。
        #   这里重启一个服务端实例来验证。
        frps_task.cancel()
        await asyncio.gather(frps_task, return_exceptions=True)
        frps_task = None
        await asyncio.sleep(1)

        logger.info("  重启服务端，udp_session_timeout = 6 秒")
        frps2 = Frps(make_frps_args(udp_session_timeout=6))
        frps_task = asyncio.create_task(frps2.start())
        if not await wait_for_clients(frps2, 1, timeout=30):
            logger.error("  客户端未能重连，该用例作废")
        await asyncio.sleep(1)

        c3 = await UdpEcho().open()
        r = await c3.request(b"will-expire")
        opened = frps2.stats.udp_sessions_active
        logger.info("  发一个包 → 回声=%r，活跃会话=%d", r, opened)
        # 回收器每 max(5, timeout//4) 秒醒一次；timeout=6 → 每 5 秒醒。
        # 等足够久，让"空闲 > 6 秒"成立并被回收。
        await asyncio.sleep(15)
        after = frps2.stats.udp_sessions_active
        results["会话超时回收"] = (r == b"will-expire" and opened >= 1 and after < opened)
        logger.info("  活跃会话 %d → %d → %s", opened, after,
                    "✅" if results["会话超时回收"] else "❌")
        c3.close()

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
        logger.info("  %-20s %s", name, "✅ 通过" if ok else "❌ 失败")
        all_ok = all_ok and ok
    logger.info("=" * 60)
    logger.info("总结论: %s", "✅ 全部通过" if all_ok else "❌ 存在失败项")
    return 0 if all_ok else 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
