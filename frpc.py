"""
frpc.py —— FRP 客户端（跑在需要被访问的内网机器上）

职责：主动连上公网 frps，把"本机服务"和"公网入口"牵起来
    · serve_port (默认 8800)：连 frps 的控制端口（走 TLS + token 鉴权）
    · local_host / local_port (默认 127.0.0.1:8080)：本机真正提供服务的地址
    · proxy_name (默认本机名)：本客户端在服务端的标识，多客户端时用来区分
    · remote_port：本客户端在服务端占用的对外端口，由本客户端自己声明

为什么要自己声明名字和端口？
    服务端不认识你，也不知道你想开在哪个端口。所以客户端一连上就"报户口"：
    "我叫 nas，我的窗口开在 9002"。服务端据此为你单独监听 9002。
    多个客户端用不同名字/端口，互不干扰。

为什么是"客户端主动连"？
    家用宽带 / 公司内网都没有公网 IP，外部连接根本进不来（NAT + 防火墙）。
    但「从里面出去」的连接一般不会被拦。所以内网机器先主动把管道打到公网服务器。

运行：
    python frpc.py --serve_host 110.110.110.1 --serve_port 8800 \\
                   --local_host 127.0.0.1 --local_port 3389 \\
                   --proxy_name rdp --remote_port 9001 \\
                   --token_file token.txt --ca_file certs/ca.crt
"""

import argparse
import asyncio
import contextlib
import logging
import os
import socket

from config import add_common_args, attach_config, remember_defaults
import about  # 作者/程序信息集中在这里（改 about.py 全项目生效）
from protocol import (
    DATA_IDLE_TIMEOUT,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_TIMEOUT,
    P2P_INFO,
    P2P_RESULT,
    PING,
    RECONNECT_INTERVAL,
    SESSION_ID_SIZE,
    Stats,
    TokenStore,
    TUNNEL_ACK,
    TUNNEL_REQ,
    UDP_ASSOC,
    UDP_CLOSE,
    UDP_DATA,
    P2PHolePuncher,
    backoff_delay,
    build_client_ssl_context,
    cancel_task,
    client_authenticate,
    close_writer,
    decode_p2p_info,
    decode_udp_assoc,
    encode_udp_close,
    encode_udp_data,
    get_logger,
    parse_log_level,
    parse_token_spec,
    read_cmd,
    read_udp_data,
    send_register,
    send_tunnel_ack,
    send_udp_tunnel_ack,
    stream_copy,
    touch,
    watchdog,
)

logger = get_logger("frpc")

# 全局持有所有隧道任务，防止 "发射后不管" 的任务被 GC 掉
TUNNEL_TASKS: "set[asyncio.Task]" = set()
# 全局持有打洞任务（同样防止被 GC）
P2P_TASKS: "set[asyncio.Task]" = set()


class LocalUdpSession(asyncio.DatagramProtocol):
    """客户端侧：一路 UDP 会话 = 一个到本机 UDP 服务的"私有套接字"。

    ★ 为什么要为每一路会话单独开一个套接字，而不是共用一个？

    因为内网 UDP 服务（DNS、游戏、RDP-UDP…）通常是**按源端口区分会话**的。
    如果所有外部用户共用一个本地套接字发出去，内网服务看到的源端口全都
    一样，就会把不同用户的会话搅在一起。

    所以：一路外部会话 → 一个本地套接字 → 一个稳定的源端口 → 内网服务
    眼中的一路独立会话。收包时按套接字把数据投回对应的 session_id。
    """

    def __init__(self, udp_client: "UdpClient", session_id: int,
                 target: "tuple[str, int]"):
        self.udp_client = udp_client
        self.session_id = session_id
        self.target = target            # 内网 UDP 服务 (host, port)
        self.transport = None
        self.closed = False

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        """收到内网 UDP 服务的回包 → 封装塞回隧道 → 服务端再转给外部用户。"""
        if self.closed:
            return
        self.udp_client.stats.udp_datagrams += 1
        self.udp_client.stats.udp_bytes += len(data)
        try:
            self.udp_client.tunnel_writer.write(
                encode_udp_data(self.session_id, data)
            )
        except Exception as exc:
            logger.debug("会话 #%d 回包写入隧道失败: %s", self.session_id, exc)

    def error_received(self, exc) -> None:
        logger.debug("会话 #%d 本地 UDP 错误: %s", self.session_id, exc)

    def connection_lost(self, exc) -> None:
        self.closed = True

    def close(self) -> None:
        self.closed = True
        if self.transport is not None:
            with contextlib.suppress(Exception):
                self.transport.close()


class UdpClient:
    """客户端侧的 UDP 转发器：一条隧道承载多路会话。

    生命周期：
        · 控制连接建立后，若配了 udp_port，就预先开一条 UDP 隧道
          （TUNNEL_ACK + 名字，服务端用 _on_udp_tunnel 接住）。
        · 服务端每分配一个新会话（UDP_ASSOC），这里就开一个本地套接字。
        · 服务端说某会话结束（UDP_CLOSE），这里关掉对应本地套接字。
        · 隧道整体断开 → 所有会话一起回收。
    """

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.tunnel_writer = None
        self.tunnel_reader = None
        self.stats: Stats = Stats()   # 由 Frpc 注入，见 attach()
        # {session_id: LocalUdpSession}
        self.sessions: "dict[int, LocalUdpSession]" = {}
        self.closed = False

    def attach(self, reader, writer, stats: Stats) -> None:
        self.tunnel_reader = reader
        self.tunnel_writer = writer
        self.stats = stats

    async def handle_assoc(self, payload: bytes) -> None:
        """处理 UDP_ASSOC：为一路会话开本地套接字。"""
        try:
            session_id, port, addr = decode_udp_assoc(payload)
        except ValueError as exc:
            logger.warning("UDP_ASSOC 解析失败: %s", exc)
            return

        if session_id in self.sessions:
            return   # 重发/重复分配，忽略

        # 目标地址：服务端若指定了 addr/port 就用它，否则用客户端自己的配置。
        host = addr or self.target_host
        target_port = port or self.target_port

        loop = asyncio.get_running_loop()

        def factory():
            return LocalUdpSession(self, session_id, (host, target_port))

        try:
            transport, protocol = await loop.create_datagram_endpoint(
                factory, remote_addr=(host, target_port)
            )
        except OSError as exc:
            logger.error("会话 #%d 无法连接内网 UDP 服务 %s:%d: %s",
                         session_id, host, target_port, exc)
            # 告诉服务端这个会话没建成，让它把外部来源那一侧也清掉
            if self.tunnel_writer is not None and not self.tunnel_writer.is_closing():
                with contextlib.suppress(Exception):
                    self.tunnel_writer.write(encode_udp_close(session_id))
            return

        self.sessions[session_id] = protocol
        logger.info("UDP 会话 #%d → 内网 %s:%d（当前 %d 路）",
                    session_id, host, target_port, len(self.sessions))

    def forward(self, session_id: int, payload: bytes) -> None:
        """把外部用户发来的 UDP 数据报转给内网服务。"""
        session = self.sessions.get(session_id)
        if session is None or session.closed or session.transport is None:
            return
        try:
            session.transport.sendto(payload)
        except Exception as exc:
            logger.debug("会话 #%d 转发到内网失败: %s", session_id, exc)

    def close_session(self, session_id: int) -> None:
        session = self.sessions.pop(session_id, None)
        if session is not None:
            session.close()
            logger.debug("UDP 会话 #%d 已回收", session_id)

    def close_all(self) -> None:
        count = len(self.sessions)
        for session in self.sessions.values():
            session.close()
        self.sessions.clear()
        self.closed = True
        if count:
            logger.info("UDP 会话全部回收（%d 路）", count)

    async def run(self) -> None:
        """UDP 隧道的读循环：处理 frps 发来的 ASSOC / DATA / CLOSE。

        ★ 这条隧道由 Frpc 在控制连接建立后拉起，常驻。
          它和普通隧道的区别是"一条 tunnel 对多个会话" —— 所以这里
          不能像 stream_copy 那样直接搬字节，必须逐帧解析。
        """
        writer = self.tunnel_writer
        reader = self.tunnel_reader
        try:
            while True:
                cmd = await read_cmd(reader)
                if not cmd:
                    logger.info("UDP 隧道已被服务端关闭")
                    return
                if cmd == UDP_ASSOC:
                    # 负载长度不定：先读 4B 会话 + 2B 端口 + 1B 地址长度 + 地址
                    head = await reader.readexactly(4 + 2 + 1)
                    addr_len = head[6]
                    addr_raw = await reader.readexactly(addr_len) if addr_len else b""
                    await self.handle_assoc(head + addr_raw)
                elif cmd == UDP_DATA:
                    session_id, payload = await read_udp_data(reader)
                    self.stats.udp_datagrams += 1
                    self.stats.udp_bytes += len(payload)
                    self.forward(session_id, payload)
                elif cmd == UDP_CLOSE:
                    session_id = decode_udp_close(
                        await reader.readexactly(SESSION_ID_SIZE)
                    )
                    self.close_session(session_id)
                else:
                    logger.debug("UDP 隧道收到未知帧 %r，忽略", cmd)
        except asyncio.CancelledError:
            raise
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
            logger.info("UDP 隧道中断: %s", exc)
        finally:
            self.close_all()


class Frpc:
    """FRP 客户端主体。"""

    def __init__(self, args):
        self.args = args
        self.stats = Stats()
        # 用 getattr 取这几个开关：让本类也能被"只填了必要字段"的
        # 调用方（如测试脚本、嵌入式用法）直接实例化，不必凑齐所有属性。
        self.ssl_ctx = build_client_ssl_context(
            ca_file=getattr(args, "ca_file", ""),
            insecure=getattr(args, "insecure", False),
            no_tls=getattr(args, "no_tls", False),
        )
        # token 也从文件读，且支持热重载 —— 轮换时不用重启客户端进程
        self.tokens = TokenStore(
            tokens=parse_token_spec(getattr(args, "token", "")),
            token_file=getattr(args, "token_file", ""),
        )
        self.proxy_name = getattr(args, "proxy_name", "") or socket.gethostname()
        # 当前控制连接对应的 UDP 转发器（没启用 UDP 时保持 None）
        self.udp_client: "UdpClient | None" = None

    @property
    def token(self) -> str:
        return self.tokens.primary

    # ------------------------------------------------------------------
    # 心跳
    # ------------------------------------------------------------------
    async def _heartbeat(self, writer) -> None:
        """向服务端补心跳，同时检测"连接假死"。

        ★ 为什么不能只发心跳？
          只发不看的话，对端早已消失（TCP 半开）而本端毫无察觉，
          会一直"对着空气"发心跳，直到你手动重启。
          这里改用统一的 watchdog：既发保活，又在"长时间收不到任何数据"
          时主动关连接，逼外层走重连流程。
        """
        await watchdog(writer, label=f"{self.proxy_name}:控制连接",
                       timeout=HEARTBEAT_TIMEOUT, interval=HEARTBEAT_INTERVAL)

    # ------------------------------------------------------------------
    # P2P 打洞（可选，失败无副作用）
    # ------------------------------------------------------------------
    async def _try_p2p(self, writer, token: bytes, server_udp_port: int) -> None:
        """尝试与**服务端**建立 UDP 直连（打洞）。

        ★ 为什么打洞在这套架构里 "收益有限但值得做"？

        本项目的典型部署是"服务端有公网 IP、客户端在内网"。这种情况下
        客户端→服务端本来就是直连的 TCP，打洞不会改变连通性。
        但打洞仍有两层价值：
          1) 把**数据面**从 TCP 换成 UDP —— 规避 TCP-over-TCP 的
             "队头阻塞"（外层 TCP 丢一个包，内层 TCP 也得整体等重传，
             在高丢包链路上延迟会成倍放大）。UDP 数据面没有这个问题。
          2) 当中间链路上 TCP 被运营商限速 / 被防火墙干扰时，
             UDP 往往还能通 —— 相当于多了一条备用路径。

        ★ 失败代价必须是 0：
          打洞尝试严格限时（默认 3 秒）；失败只记一条日志，
          原有 TCP 中转**完全不受影响**，用户无感。
        """
        puncher = P2PHolePuncher(token)
        ok = False
        try:
            await puncher.open(0)
            self.stats.p2p_attempts += 1
            logger.info("[%s] 尝试与 %s:%d 打洞（限时 %.1f 秒）……",
                        self.proxy_name, self.args.serve_host, server_udp_port,
                        self.cfg_p2p_timeout())
            ok = await puncher.attempt(
                self.args.serve_host, server_udp_port,
                timeout=self.cfg_p2p_timeout(),
            )
        except Exception as exc:
            logger.info("[%s] 打洞过程异常（忽略，继续用中转）: %s",
                        self.proxy_name, exc)
            ok = False
        finally:
            # 无论成败都要回报服务端：服务端据此打日志 / 计数。
            # ★ 用 try 包住，回报失败绝不允许影响主流程。
            with contextlib.suppress(Exception):
                writer.write(P2P_RESULT + (b"\x01" if ok else b"\x00"))
                await writer.drain()
            if ok:
                logger.info("[%s] P2P 打洞成功：与服务端之间的 UDP 通道已连通",
                            self.proxy_name)
            else:
                logger.info("[%s] P2P 打洞未成功（对称 NAT / 超时），"
                            "保持原有的 TCP 中转，服务不受影响", self.proxy_name)
            puncher.close()

    def cfg_p2p_timeout(self) -> float:
        return float(getattr(self.args, "p2p_timeout", 3.0) or 3.0)

    # ------------------------------------------------------------------
    # 隧道
    # ------------------------------------------------------------------
    async def _open_tunnel(self) -> None:
        """建立一条隧道：服务端 ↔ 本机 local_port。

            服务端隧道连接 ──stream_copy──▶ 本地服务
            服务端隧道连接 ◀──stream_copy── 本地服务

        隧道连接同样要过鉴权 —— 不然别人可以绕过控制通道，
        直接连 serve_port 冒充隧道，把数据引到别处。
        """
        serve_writer = None
        try:
            serve_reader, serve_writer = await asyncio.open_connection(
                self.args.serve_host, self.args.serve_port, ssl=self.ssl_ctx
            )
            if not await client_authenticate(serve_reader, serve_writer, self.token):
                logger.error("隧道连接鉴权失败")
                await close_writer(serve_writer)
                return

            # 声明这条隧道属于哪个客户端 —— 服务端据此路由到正确的 Session
            await send_tunnel_ack(serve_writer, self.proxy_name)

            local_reader, local_writer = await asyncio.open_connection(
                self.args.local_host, self.args.local_port
            )
        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            logger.error("建立隧道失败: %s", exc)
            await close_writer(serve_writer)
            return

        self.stats.tunnels_established += 1
        self.stats.connections_active += 1
        logger.info("[%s] 隧道已建立：服务端 ⇄ %s:%s",
                    self.proxy_name, self.args.local_host, self.args.local_port)
        try:
            await asyncio.gather(
                # ★ idle_timeout：数据隧道没法靠心跳字节保活（会污染用户数据），
                #   只能靠"长期收不到数据 = 连接已死"来兜住 TCP 半开。
                #   取一个较宽松的值，正常业务几乎不会触发。
                stream_copy(serve_reader, local_writer, "外网→本地", self.stats,
                            idle_timeout=DATA_IDLE_TIMEOUT),
                stream_copy(local_reader, serve_writer, "本地→外网", self.stats,
                            idle_timeout=DATA_IDLE_TIMEOUT),
            )
        finally:
            self.stats.connections_active -= 1
            logger.info("[%s] 隧道关闭", self.proxy_name)

    # ------------------------------------------------------------------
    # 控制连接
    # ------------------------------------------------------------------
    async def _open_udp_tunnel(self) -> None:
        """建立"UDP 承载隧道" —— 一条连接，承载该客户端的全部 UDP 会话。

        这条隧道本身是 TCP（复用 TLS + 鉴权），里面跑的是带会话头的帧。
        UDP 的所有会话都复用这一条，避免"一个 UDP 包一条连接"的灾难。
        """
        tunnel_writer = None
        try:
            reader, tunnel_writer = await asyncio.open_connection(
                self.args.serve_host, self.args.serve_port, ssl=self.ssl_ctx
            )
            if not await client_authenticate(reader, tunnel_writer, self.token):
                logger.error("UDP 隧道鉴权失败")
                await close_writer(tunnel_writer)
                return
            # 声明这是哪个客户端的 UDP 隧道（服务端据此挂到对应 Session 的 UDP 前端）
            await send_udp_tunnel_ack(tunnel_writer, self.proxy_name)
        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            logger.error("建立 UDP 隧道失败: %s", exc)
            await close_writer(tunnel_writer)
            return

        logger.info("[%s] UDP 隧道已建立（将按需承载多路 UDP 会话）", self.proxy_name)
        udp_target_port = (getattr(self.args, "udp_local_port", 0)
                           or self.args.local_port)
        udp_client = UdpClient(self.args.local_host, udp_target_port)
        self.udp_client = udp_client
        udp_client.attach(reader, tunnel_writer, self.stats)
        try:
            await udp_client.run()
        finally:
            self.udp_client = None
            logger.info("[%s] UDP 隧道已结束", self.proxy_name)

    # ------------------------------------------------------------------
    # 控制连接
    # ------------------------------------------------------------------
    async def _run_once(self) -> None:
        """建立一次控制连接并服务，直到断开（断开后由外层重连）。"""
        reader, writer = await asyncio.open_connection(
            self.args.serve_host, self.args.serve_port, ssl=self.ssl_ctx
        )
        logger.info("[%s] 已连接服务端 %s:%s（TLS 已就绪）",
                    self.proxy_name, self.args.serve_host, self.args.serve_port)

        # 第一步：鉴权
        if not await client_authenticate(reader, writer, self.token):
            self.stats.auth_failures += 1
            await close_writer(writer)
            raise ConnectionError("鉴权未通过")

        # 第二步：报户口（名字 + 声明的对外端口），并表明这是控制连接
        writer.write(PING)
        await writer.drain()
        await send_register(writer, self.proxy_name, self.args.remote_port,
                            getattr(self.args, "udp_port", 0) or 0)
        logger.info("[%s] 鉴权通过，已注册（TCP 端口 %d%s），进入控制循环",
                    self.proxy_name, self.args.remote_port,
                    "，UDP 端口 %d" % self.args.udp_port
                    if getattr(self.args, "udp_port", 0) else "")

        heartbeat_task = asyncio.create_task(self._heartbeat(writer))
        touch(writer)   # 给 watchdog 一个初始时刻，避免它一上来就误判
        # 若本客户端配了 UDP，就预先开一条常驻 UDP 隧道。
        # ★ 为什么"预开"而不是"等有包再开"？
        #   TCP 是"有用户 → 通知客户端 → 现开隧道"，来得及；
        #   UDP 的包是随时冒出来的，等包到了再建连，那个包已经丢了。
        udp_task = None
        if (getattr(self.args, "udp_port", 0) or 0):
            udp_task = asyncio.create_task(self._open_udp_tunnel())
        try:
            while True:
                cmd = await read_cmd(reader)
                if not cmd:
                    raise ConnectionError("服务端已关闭连接")
                touch(writer)   # 收到任何字节都要登记，watchdog 据此判假死
                if cmd == PING:
                    logger.debug("[%s] 收到心跳回应", self.proxy_name)
                elif cmd == P2P_INFO:
                    # 服务端下发打洞参数：共享 token + 服务端 UDP 端口
                    try:
                        payload = await reader.readexactly(16 + 2)
                    except (asyncio.IncompleteReadError, ConnectionError, OSError):
                        raise ConnectionError("读取 P2P 参数失败")
                    if getattr(self.args, "no_p2p", False):
                        logger.debug("[%s] 已禁用 P2P（--no_p2p），忽略打洞参数",
                                     self.proxy_name)
                        continue
                    try:
                        token, udp_port = decode_p2p_info(payload)
                    except ValueError as exc:
                        logger.warning("[%s] P2P 参数解析失败: %s", self.proxy_name, exc)
                        continue
                    p2p_task = asyncio.create_task(
                        self._try_p2p(writer, token, udp_port)
                    )
                    P2P_TASKS.add(p2p_task)
                    p2p_task.add_done_callback(P2P_TASKS.discard)
                elif cmd == TUNNEL_REQ:
                    logger.info("[%s] 服务端通知有新用户，开隧道", self.proxy_name)
                    # ★ 关键：不能 await _open_tunnel()，否则整条控制连接会被它独占。
                    task = asyncio.create_task(self._open_tunnel())
                    TUNNEL_TASKS.add(task)
                    task.add_done_callback(TUNNEL_TASKS.discard)
                else:
                    logger.warning("[%s] 收到未知指令 %r，忽略", self.proxy_name, cmd)
        finally:
            await cancel_task(heartbeat_task)
            await cancel_task(udp_task)
            await close_writer(writer)

    # ------------------------------------------------------------------
    # 主循环
    # ------------------------------------------------------------------
    async def start(self) -> None:
        stats_task = asyncio.create_task(self._periodic_stats())
        token_task = asyncio.create_task(self._token_watch())
        attempt = 0
        try:
            while True:
                try:
                    await self._run_once()
                    attempt = 0            # 正常跑过一轮（哪怕很短）也算"连通了"
                except asyncio.CancelledError:
                    await self._cancel_tunnels()
                    raise
                except (ConnectionError, OSError) as exc:
                    logger.warning("[%s] 连接异常: %s", self.proxy_name, exc)
                except Exception as exc:
                    logger.error("[%s] 未预期错误: %s", self.proxy_name, exc)
                # ★ 指数退避 + 抖动：见 protocol.backoff_delay 的说明。
                #   重点解决两个现实问题：
                #     1) 服务端重启时，几百个客户端不要在同 1 秒齐步重连（惊群）；
                #     2) 网络抖动时又能较快恢复（退避从小值开始）。
                attempt += 1
                delay = backoff_delay(attempt)
                logger.info("[%s] %.1f 秒后重连（第 %d 次）……",
                            self.proxy_name, delay, attempt)
                await asyncio.sleep(delay)
        finally:
            await cancel_task(stats_task)
            await cancel_task(token_task)

    async def _periodic_stats(self) -> None:
        while True:
            await asyncio.sleep(60)
            logger.info("[%s] 统计 | %s", self.proxy_name, self.stats.summary())

    async def _token_watch(self) -> None:
        """token 文件变化时热重载 —— 轮换时无需重启本进程。"""
        while True:
            await asyncio.sleep(5)
            self.tokens.reload_from_file()

    async def _cancel_tunnels(self) -> None:
        tasks = [t for t in TUNNEL_TASKS if not t.done()]
        tasks += [t for t in P2P_TASKS if not t.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


async def main(args) -> None:
    await Frpc(args).start()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="FRP 客户端（多客户端 / token 轮换支持）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # 网络
    parser.add_argument("--serve_host", default="localhost", help="FRP 服务端地址")
    parser.add_argument("--serve_port", type=int, default=8800, help="FRP 服务端控制端口")
    parser.add_argument("--local_host", default="127.0.0.1", help="本机服务地址")
    parser.add_argument("--local_port", type=int, default=8080, help="本机服务端口")
    # 身份（多客户端路由）
    parser.add_argument("--proxy_name", default="",
                        help="本客户端在服务端的名字（默认取主机名），多客户端时必须唯一")
    parser.add_argument("--remote_port", type=int, default=0,
                        help="在服务端占用的对外 TCP 端口（必填），如 9001")
    # UDP（可选）
    parser.add_argument("--udp_port", type=int, default=0,
                        help="在服务端占用的对外 UDP 端口（可选）。填了才启用 UDP 转发；"
                             "通常与 remote_port 同号，如 3389")
    parser.add_argument("--udp_local_port", type=int, default=0,
                        help="本机 UDP 服务端口（默认与 local_port 相同）")
    # P2P 打洞（可选）
    parser.add_argument("--p2p_timeout", type=float, default=3.0,
                        help="打洞探测的最长等待秒数；超时即放弃并继续走中转")
    parser.add_argument("--no_p2p", action="store_true",
                        help="完全不做打洞探测（只走中转）")
    # 安全
    parser.add_argument("--token", default="", help="共享密钥（须与服务端之一一致）")
    parser.add_argument("--token_file", default="",
                        help="从文件读取 token（每行一个）；支持热重载，便于轮换")
    parser.add_argument("--ca_file", default="", help="CA 证书（校验服务端身份）")
    parser.add_argument("--insecure", action="store_true",
                        help="跳过证书校验（自签证书临时测试用，勿用于生产）")
    parser.add_argument("--no_tls", action="store_true",
                        help="完全不用 TLS（仅当服务端也未配证书时使用，明文传输）")
    # 日志
    parser.add_argument("--log_level", default="INFO",
                        help="日志级别 DEBUG/INFO/WARNING/ERROR")
    # 作者信息
    parser.add_argument("--about", action="store_true",
                        help="显示程序与作者信息后退出")
    # 配置文件（极简调用：python frpc.py -c client.toml）
    add_common_args(parser)
    remember_defaults(parser)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.about:                  # --about：只打印信息，不启动客户端
        print(about.summary())
        for _k, _v in about.author_lines():
            print("  %s：%s" % (_k, _v))
        raise SystemExit(0)
    attach_config(args, logger)     # 套用配置文件（命令行优先）

    if not args.token and not args.token_file:
        logger.error("必须通过 --token / --token_file 指定共享密钥（或在配置文件里配 token）")
        raise SystemExit(2)
    if not args.remote_port:
        logger.error("必须指定在服务端占用的对外端口（--remote_port 或配置里的 remote_port）")
        raise SystemExit(2)
    if args.token_file and not args.token and not os.path.exists(args.token_file):
        logger.error("token 文件不存在：%s", args.token_file)
        raise SystemExit(2)

    logger.setLevel(parse_log_level(args.log_level))
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        logger.info("已手动退出")
