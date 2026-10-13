"""
frps.py —— FRP 服务端（跑在有公网 IP 的机器上）

职责：站在公网侧，同时监听两类端口
    · serve_port (默认 8800)：给内网的 frpc 连，属于「控制 + 隧道」通道
    · 用户端口：**每个客户端各占一个**，由客户端注册时声明，服务端动态监听

一个生动的类比：
    frps 是"快递中转站"，每个 frpc 是不同城市来的"取件小哥"。
    每个小哥在总台登记："我叫 nas，我的取件窗口开在 9002 号"。
    中转站就为它单独开一个 9002 窗口。外部用户送到 9002 的包裹，
    只会通知 nas 这个小哥来取，不会串到别人家。

本版本新增的三项能力：
    1. 多客户端      —— 按名字路由，每个客户端独立用户端口，互不干扰
    2. token 轮换    —— 新旧 token 并存过渡期；支持从文件热重载
    3. 证书自动续期  —— 启动时 + 每天定时检查，临期自动用 CA 重签并热加载

运行：
    python frps.py --serve_host 0.0.0.0 --serve_port 8800 \\
                   --token_file tokens.txt \\
                   --cert_file certs/server.crt --key_file certs/server.key \\
                   --ca_cert_file certs/ca.crt --ca_key_file certs/ca.key \\
                   --cert_host 你的服务器IP
"""

import argparse
import asyncio
import contextlib
import logging
import os
import socket

from cert_renew import cert_renew_loop, ensure_valid_cert
from config import add_common_args, attach_config, remember_defaults
import about  # 作者/程序信息集中在这里（改 about.py 全项目生效）
from protocol import (
    AUTH_FAIL,
    DATA_IDLE_TIMEOUT,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_TIMEOUT,
    P2P_INFO,
    P2P_RESULT,
    P2P_TOKEN_SIZE,
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
    UDP_SESSION_TIMEOUT,
    UDP_TUNNEL,
    USER_CONN_TIMEOUT,
    build_server_ssl_context,
    cancel_task,
    cert_days_left,
    close_writer,
    decode_udp_close,
    encode_p2p_info,
    encode_udp_assoc,
    encode_udp_close,
    encode_udp_data,
    get_logger,
    parse_log_level,
    parse_token_spec,
    read_cmd,
    read_register,
    read_tunnel_ack,
    read_udp_data,
    server_authenticate,
    stream_copy,
    touch,
    watchdog,
)

logger = get_logger("frps")


class RateLimiter:
    """连接限流器（全局维度）。

    注意：单 IP 的连接数限制是**每个客户端独立**的（放在 Session 里），
    因为不同客户端有不同的对外端口，一个 IP 同时连两个客户端的服务
    不应该被算成"连了两次同一个服务"。
    这里只保留全局维度的限制。
    """

    def __init__(self, max_active: int, max_queued: int):
        self.max_active = max_active
        self.max_queued = max_queued
        self._active_total = 0           # 当前活跃转发数
        self._queued = 0                 # 当前排队数

    def active_acquire(self) -> bool:
        if self._active_total >= self.max_active:
            return False
        self._active_total += 1
        return True

    def active_release(self) -> None:
        if self._active_total > 0:
            self._active_total -= 1

    def enqueue(self) -> bool:
        if self._queued >= self.max_queued:
            return False
        self._queued += 1
        return True

    def dequeue(self) -> None:
        if self._queued > 0:
            self._queued -= 1

    @property
    def snapshot(self) -> str:
        return f"活跃 {self._active_total}/{self.max_active} 排队 {self._queued}/{self.max_queued}"


class UdpSession:
    """一路外部来源地址（IP:port）对应的一条 UDP 会话。

    ★ 为什么要有它，而不是"每个 UDP 包现开一条隧道"？

    UDP 是无连接的，同一个客户端会连续发很多个包。如果每个包都开一条
    到内网的隧道，会有两个致命问题：
      1) 开销爆炸：每包一次握手 + 一次 TCP 建连；
      2) **会话被打散**：内网 UDP 服务端会看到"每个包来自不同源端口"，
         像 DNS / RDP / 游戏这类有会话状态的服务立刻就不认了。

    所以正确做法是：按【来源地址】建会话 —— 同一个源地址持续复用同一条
    会话（以及隧道那一头的同一个本地套接字），源端口对内网服务保持稳定。
    """

    def __init__(self, session_id: int, peer: "tuple[str, int]",
                 target_port: int, target_addr: str, transport):
        self.session_id = session_id
        self.peer = peer                      # 外部来源地址 (ip, port)
        self.target_port = target_port        # 内网 UDP 服务端口
        self.target_addr = target_addr        # 内网 UDP 服务地址（通常为空）
        self.transport = transport            # 回包时用来 sendto(peer)
        self.last_active = asyncio.get_event_loop().time()
        self.closed = False

    def touch(self) -> None:
        self.last_active = asyncio.get_event_loop().time()

    @property
    def idle(self) -> float:
        return asyncio.get_event_loop().time() - self.last_active


class UdpFrontend(asyncio.DatagramProtocol):
    """服务端侧的 UDP 对外监听口（一个客户端一个端口）。

    datagram_received 每收到一个外部 UDP 包就被调用一次。这里负责：
      1) 按来源地址找会话；找不到就新建一个（分配 session_id）
      2) 把包封装成 UDP_DATA 帧，写进该客户端已建立的 UDP 隧道
      3) 会话空闲超时后回收

    ★ 一个关键限制：UDP 隧道是"每个客户端一条"（在控制通道建立时用
      UDP_ASSOC 申请），而不是每个外部用户一条。这是为了配合"多条会话
      复用一条隧道"的设计 —— 否则 UDP 又要回到"每包一条连接"的老路。
    """

    def __init__(self, frps: "Frps", name: str, remote_port: int,
                 target_port: int, target_addr: str = ""):
        self.frps = frps
        self.name = name
        self.remote_port = remote_port
        self.target_port = target_port
        self.target_addr = target_addr
        self.transport = None
        # {来源地址: UdpSession}
        self.sessions: "dict[tuple[str, int], UdpSession]" = {}
        # {session_id: UdpSession}（回包时按 id 找到该发给谁）
        self.by_id: "dict[int, UdpSession]" = {}
        self._next_id = 1
        self._reaper_task: "asyncio.Task | None" = None
        self.closed = False

    # --- DatagramProtocol 回调 ---
    def connection_made(self, transport) -> None:
        self.transport = transport
        self._reaper_task = asyncio.create_task(self._reap_idle())

    def datagram_received(self, data: bytes, addr) -> None:
        """收到一个外部 UDP 数据报。"""
        if self.closed:
            return
        session = self.sessions.get(addr)
        if session is None:
            session = self._open_session(addr)
            if session is None:
                return
        session.touch()

        writer = self.frps.udp_tunnels.get(self.name)
        if writer is None or writer.is_closing():
            # 隧道还没建好（客户端刚接入、隧道正在建）—— 直接丢掉这个包。
            # ★ 不能在这里"等一下再发"：UDP 是不可靠的，丢掉一个包本身
            #   是可接受的语义；而积压反而会造成突发。
            self.frps.stats.udp_rejected += 1
            if not self.frps._udp_warned.get(self.name):
                self.frps._udp_warned[self.name] = True
                logger.warning("[%s] UDP 隧道尚未就绪，暂时丢弃数据报（客户端会很快补建）",
                               self.name)
            return

        self.frps.stats.udp_datagrams += 1
        self.frps.stats.udp_bytes += len(data)
        try:
            writer.write(encode_udp_data(session.session_id, data))
        except Exception as exc:
            logger.debug("[%s] UDP 写入隧道失败: %s", self.name, exc)

    def error_received(self, exc) -> None:
        logger.debug("[%s] UDP 收发错误: %s", self.name, exc)

    def connection_lost(self, exc) -> None:
        self.closed = True
        if self._reaper_task is not None:
            self._reaper_task.cancel()

    # --- 会话管理 ---
    def _open_session(self, addr) -> "UdpSession | None":
        """为一个新的来源地址建会话，并通知 frpc 分配对应的内网通道。"""
        max_sessions = self.frps.cfg("max_udp_sessions", 512)
        if len(self.sessions) >= max_sessions:
            self.frps.stats.udp_rejected += 1
            logger.warning("[%s] UDP 会话数已达上限 %d，丢弃来自 %s 的数据报",
                           self.name, max_sessions, addr)
            return None

        session_id = self._next_id
        self._next_id = (self._next_id + 1) & 0xFFFFFFFF or 1  # 回绕时跳过 0

        session = UdpSession(session_id, addr, self.target_port,
                             self.target_addr, self.transport)
        self.sessions[addr] = session
        self.by_id[session_id] = session
        self.frps.stats.udp_sessions_opened += 1
        self.frps.stats.udp_sessions_active += 1
        logger.info("[%s] 新 UDP 会话 #%d ← %s:%d（当前 %d 路）",
                    self.name, session_id, addr[0], addr[1], len(self.sessions))

        # 通知 frpc：为这个 session_id 建一条到内网 UDP 服务的通道
        writer = self.frps.udp_tunnels.get(self.name)
        if writer is not None and not writer.is_closing():
            try:
                writer.write(encode_udp_assoc(session_id, self.target_port,
                                              self.target_addr))
            except Exception as exc:
                logger.debug("[%s] 发送 UDP_ASSOC 失败: %s", self.name, exc)
        return session

    def close_session(self, session_id: int, notify: bool = True) -> None:
        """关闭一路会话（收到 frpc 的 UDP_CLOSE，或空闲超时）。"""
        session = self.by_id.pop(session_id, None)
        if session is None:
            return
        session.closed = True
        self.sessions.pop(session.peer, None)
        self.frps.stats.udp_sessions_active = max(
            0, self.frps.stats.udp_sessions_active - 1
        )
        if notify:
            writer = self.frps.udp_tunnels.get(self.name)
            if writer is not None and not writer.is_closing():
                with contextlib.suppress(Exception):
                    writer.write(encode_udp_close(session_id))
        logger.debug("[%s] UDP 会话 #%d 关闭", self.name, session_id)

    def close_all(self) -> None:
        """隧道断开时整体清理（frpc 那头的本地套接字也会随之释放）。"""
        count = len(self.sessions)
        self.sessions.clear()
        self.by_id.clear()
        if count:
            self.frps.stats.udp_sessions_active = max(
                0, self.frps.stats.udp_sessions_active - count
            )
            logger.info("[%s] UDP 会话全部回收（%d 路）", self.name, count)

    async def _reap_idle(self) -> None:
        """周期性回收空闲会话。

        UDP 没有"关闭"语义，只能靠"多久没动静"来判断会话结束。
        不回收的话，长期运行会把会话表撑满（每个外部源地址都留一条）。
        """
        timeout = self.frps.cfg("udp_session_timeout", UDP_SESSION_TIMEOUT)
        try:
            while True:
                await asyncio.sleep(max(5, timeout // 4))
                dead = [s.session_id for s in list(self.sessions.values())
                        if s.idle > timeout]
                for sid in dead:
                    self.close_session(sid)
        except asyncio.CancelledError:
            raise


class PendingUser:
    """一个排队等待隧道的外部用户连接。

    ★ 为什么不能像早先那样"读 1 个字节看连接还在不在"？
      那个写法会把用户的**第一个字节吃掉**：HTTP 的 `GET ` 变成 `ET `，
      RDP 的协议握手首字节直接被吞 —— 真实服务端会当成非法请求拒掉。
      而且它测的也不是"连接是否还活着"，只是"有没有数据先到"：
      如果用户先等服务器说话（很多协议都是服务端先发 banner：
      SMTP / MySQL / Redis / FTP …），这个连接就会被误判超时踢掉。

      这里改成事件驱动：隧道真正接管这条连接时，把 `taken` 置位；
      `handle_user` 只是等这个事件，**完全不碰用户的数据**。
    """

    __slots__ = ("reader", "writer", "taken")

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.taken = asyncio.Event()


class Session:
    """一个内网客户端（一个"小哥"）的完整状态。

    每个 Session 自己持有：
        · 控制连接          —— 收心跳、发"有新用户"通知
        · 待服务用户队列    —— 按序服务该客户端的用户
        · 单 IP 连接计数    —— 这个客户端自己的限流
    """

    def __init__(self, name: str, reader, writer, max_per_ip: int):
        self.name = name
        self.reader = reader
        self.writer = writer
        self.pending_users: asyncio.Queue = asyncio.Queue()
        self.closed = False
        self.max_per_ip = max_per_ip
        self._per_ip: dict = {}
        self.connected_at = asyncio.get_event_loop().time()
        # 客户端声明的 UDP 对外端口（0 = 不启用 UDP）
        self.udp_port = 0

    # --- 单 IP 计数（本客户端维度） ---
    def ip_acquire(self, ip: str) -> bool:
        cur = self._per_ip.get(ip, 0)
        if cur >= self.max_per_ip:
            return False
        self._per_ip[ip] = cur + 1
        return True

    def ip_release(self, ip: str) -> None:
        if self._per_ip.get(ip, 0) <= 1:
            self._per_ip.pop(ip, None)
        else:
            self._per_ip[ip] -= 1

    async def notify_new_user(self) -> bool:
        """有新用户接入，通知 frpc 开隧道。

        注意这里**只发一个字节**，不带名字 —— 因为这条连接本身就是
        "专属"的（是 frps 主动从该 Session 的控制连接发出去的），
        对方一看就知道是给它的。
        """
        if self.closed:
            return False
        try:
            self.writer.write(TUNNEL_REQ)
            await self.writer.drain()
            return True
        except (ConnectionError, OSError) as exc:
            logger.warning("[%s] 通知客户端失败（可能已掉线）: %s", self.name, exc)
            self.closed = True
            return False

    async def serve_forever(self, stats: Stats) -> None:
        """控制连接主循环：收发心跳，直到连接断开或判定假死。

        ★ 改动点：原来用 `wait_for(read_cmd, HEARTBEAT_INTERVAL*3)` 做
          "超时即掉线"。那个办法只能覆盖"服务端在读"的时刻；一旦
          客户端只是在发数据而服务端恰好没在读，或反之，就可能误判。
          现在统一交给 watchdog：它同时负责"发保活"和"查假死"，
          并把判据建立在"收到过对端任何字节"这一事实上。
        """
        hearbeat_task = asyncio.create_task(
            watchdog(self.writer, label=f"{self.name}:控制连接",
                     timeout=HEARTBEAT_TIMEOUT, interval=HEARTBEAT_INTERVAL)
        )
        touch(self.writer)
        try:
            while True:
                cmd = await read_cmd(self.reader)
                if not cmd:
                    logger.info("[%s] 客户端连接已关闭", self.name)
                    break
                touch(self.writer)
                if cmd == P2P_RESULT:
                    # 客户端回报打洞结果（1 字节：1=成功 0=失败）
                    try:
                        flag = await self.reader.readexactly(1)
                    except (asyncio.IncompleteReadError, ConnectionError, OSError):
                        break
                    ok = flag == b"\x01"
                    if ok:
                        stats.p2p_success += 1
                    logger.info("[%s] P2P 打洞%s（累计 尝试%d 成功%d）",
                                self.name, "成功，数据面已走 UDP 直连" if ok
                                else "失败，继续走中转",
                                stats.p2p_attempts, stats.p2p_success)
                    continue
                if cmd != PING:
                    logger.warning("[%s] 收到未知指令 %r，断开", self.name, cmd)
                    break
                logger.debug("[%s] 收到心跳，回 pong", self.name)
                self.writer.write(PING)
                await self.writer.drain()
        except (ConnectionError, OSError) as exc:
            logger.info("[%s] 客户端连接中断: %s", self.name, exc)
        finally:
            self.closed = True
            await cancel_task(hearbeat_task)
            await close_writer(self.writer)

    def take_user(self):
        """取出一个等待服务的用户连接（非阻塞）。"""
        try:
            return self.pending_users.get_nowait()
        except asyncio.QueueEmpty:
            return None


class Frps:
    """FRP 服务端主体（支持多客户端）。"""

    def __init__(self, args):
        self.args = args
        self.stats = Stats()
        # 统一用 getattr 取配置：既让"只填必要字段"的调用方（测试脚本、
        # 嵌入式用法）能直接实例化，也让新增参数不会破坏老调用代码。
        g = lambda k, d=None: getattr(args, k, d)
        self.tokens = TokenStore(
            tokens=parse_token_spec(g("token", "")),
            token_file=g("token_file", ""),
        )
        self.limiter = RateLimiter(
            max_active=g("max_active_conns", 100),
            max_queued=g("max_queued", 50),
        )
        # 多客户端路由表：{客户端名字: Session}
        self.sessions: "dict[str, Session]" = {}
        # 已注册名字 → 用户监听口。客户端重连时名字相同则复用同一端口。
        self._user_servers: "dict[str, asyncio.AbstractServer]" = {}
        self._session_tasks: "dict[str, asyncio.Task]" = {}
        # 用户监听口任务（每个客户端一个）
        self._user_server_tasks: "dict[str, asyncio.Task]" = {}
        # --- UDP ---
        # {客户端名字: StreamWriter} —— 该客户端的 UDP 隧道（一条隧道承载多路会话）
        self.udp_tunnels: "dict[str, asyncio.StreamWriter]" = {}
        # {客户端名字: UdpFrontend} —— 该客户端的 UDP 对外监听口
        self._udp_frontends: "dict[str, UdpFrontend]" = {}
        # {客户端名字: (transport, protocol)} —— 用于关闭监听口
        self._udp_transports: "dict[str, asyncio.DatagramTransport]" = {}
        # 已经就"隧道未就绪"告警过的客户端，避免刷屏
        self._udp_warned: "dict[str, bool]" = {}
        # --- P2P 打洞 ---
        # 本次运行统一的打洞 token（双方共享）。进程启动时随机生成一次，
        # 所有客户端共用 —— 因为它只是"确认探测包来自本服务"的标记，
        # 不需要每个客户端一个（省得维护一张表）。
        self.p2p_token: bytes = os.urandom(P2P_TOKEN_SIZE)
        # 打洞用的 UDP 监听端口（供客户端往这里打）。0 = 未启用。
        self.p2p_udp_port: int = 0
        self._p2p_transport = None
        # TLS 上下文
        self.ssl_ctx = None
        if g("cert_file") and g("key_file"):
            self.ssl_ctx = build_server_ssl_context(g("cert_file"), g("key_file"))
        self._token_watch_task = None

    def cfg(self, key: str, default=None):
        """读取一项配置，缺失时返回默认值。

        统一入口的好处：新增配置项不会因为"老调用方没填这个字段"而崩，
        也让上层代码少写一堆 getattr 噪音。
        """
        return getattr(self.args, key, default)

    # ------------------------------------------------------------------
    # 面向 frpc 的连接
    # ------------------------------------------------------------------
    async def handle_frpc(self, reader, writer) -> None:
        """frpc 连上 serve_port 后的总入口：先鉴权，再按指令分流。"""
        # 第一步：鉴权。没通过的直接断开。
        try:
            ok = await asyncio.wait_for(
                server_authenticate(reader, writer, self.tokens), timeout=15
            )
        except asyncio.TimeoutError:
            ok = False
        if not ok:
            self.stats.auth_failures += 1
            logger.warning("拒绝一个未通过鉴权的连接 %s", writer.get_extra_info("peername"))
            with contextlib.suppress(Exception):
                writer.write(AUTH_FAIL)
                await writer.drain()
            await close_writer(writer)
            return

        # 第二步：看接下来是什么指令
        #   注意：隧道连接比控制连接少一步注册 —— 它已经鉴权过了，
        #   接下来直接发 TUNNEL_ACK + 名字，由服务端路由。
        cmd = await read_cmd(reader)
        if cmd == PING:
            await self._on_control_connected(reader, writer)
        elif cmd == TUNNEL_ACK:
            await self._on_tunnel_ready(reader, writer)
        elif cmd == UDP_TUNNEL:
            await self._on_udp_tunnel(reader, writer)
        else:
            logger.warning("客户端指令非法 %r，断开", cmd)
            await close_writer(writer)

    async def _on_control_connected(self, reader, writer) -> None:
        """控制连接：读取注册信息 → 登记 Session → 确保用户端口在监听 → 心跳。"""
        try:
            name, remote_port, udp_port = await read_register(reader)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                ConnectionError, OSError, ValueError) as exc:
            logger.warning("读取客户端注册信息失败: %s", exc)
            await close_writer(writer)
            return

        if not name:
            logger.warning("客户端未提供名字，拒绝接入")
            await close_writer(writer)
            return
        if not remote_port:
            logger.warning("[%s] 未声明对外端口，拒绝接入", name)
            await close_writer(writer)
            return

        # 同名客户端重连：关掉旧的 Session，用新的接管
        old = self.sessions.get(name)
        if old is not None:
            logger.info("[%s] 同名客户端重连，替换旧会话", name)
            old.closed = True
            with contextlib.suppress(Exception):
                self.sessions.pop(name, None)

        session = Session(name, reader, writer, self.cfg("max_conn_per_ip", 20))
        # 记下该客户端声明的 UDP 对外端口（0 表示不启用 UDP）
        session.udp_port = udp_port
        self.sessions[name] = session
        self._session_tasks[name] = asyncio.current_task()
        logger.info("[%s] 已接入 %s（鉴权通过，对外端口 %d%s，当前在线 %d 个客户端）",
                    name, writer.get_extra_info("peername"), remote_port,
                    f"，UDP %d" % udp_port if udp_port else "",
                    len(self.sessions))

        # 确保这个客户端的用户端口处于监听状态
        await self._ensure_user_port(name, remote_port)
        # 若客户端声明了 UDP，则同时开 UDP 对外端口
        if udp_port:
            await self._ensure_udp_port(name, udp_port)

        # 通知客户端打洞参数（若服务端开了打洞口）。
        # ★ 放在注册之后、进入心跳循环之前：客户端一到手就可以尝试打洞，
        #   打不通也没关系 —— 它本来就在走中转，打洞只是"锦上添花"。
        if self.p2p_udp_port:
            with contextlib.suppress(Exception):
                writer.write(encode_p2p_info(self.p2p_token, self.p2p_udp_port))
                await writer.drain()
            self.stats.p2p_attempts += 1

        try:
            await session.serve_forever(self.stats)
        finally:
            if self.sessions.get(name) is session:
                self.sessions.pop(name, None)
                self._session_tasks.pop(name, None)
            # 控制连接断开 = 客户端整体离线：UDP 会话与隧道一并清理
            await self._drop_udp(name)
            logger.info("[%s] 已断开，等待重连……", name)

    async def _ensure_user_port(self, name: str, port: int) -> None:
        """为某个客户端启动（或复用）它的对外用户端口监听。

        客户端重连时端口通常不变，直接复用已有的监听口，
        避免"关掉再开"造成短暂的服务中断。
        """
        existing = self._user_servers.get(name)
        if existing is not None:
            # 端口一致 → 复用；不一致 → 重建（用户改了配置）
            if self._server_port(existing) == port:
                logger.info("[%s] 复用已存在的用户端口 %d", name, port)
                return
            logger.info("[%s] 对外端口由 %s 变更为 %d，重建监听",
                        name, self._server_port(existing), port)
            await self._stop_user_server(name)

        async def handler(reader, writer):
            await self.handle_user(name, reader, writer)

        try:
            server = await asyncio.start_server(
                self._spawn(handler), host=self.cfg("user_host", "0.0.0.0"), port=port,
                ssl=self.ssl_ctx,
            )
        except OSError as exc:
            logger.error("[%s] 无法监听用户端口 %d: %s（可能被占用）", name, port, exc)
            return

        self._user_servers[name] = server
        # ★ 同样不用 server.serve_forever()：它在被取消时会 await wait_closed()，
        #   而这个用户端口上往往正挂着等待配对的外部用户连接 → 取消即悬挂。
        #   改成"空转等待"，取消无副作用。
        self._user_server_tasks[name] = asyncio.create_task(self._idle_forever())
        logger.info("[%s] 用户端口已监听 %s:%d%s", name, self.cfg("user_host", "0.0.0.0"), port,
                    " [TLS]" if self.ssl_ctx else " [明文]")

    @staticmethod
    def _server_port(server: asyncio.AbstractServer) -> "int | None":
        try:
            return server.sockets[0].getsockname()[1]
        except (IndexError, AttributeError, OSError):
            return None

    async def _stop_user_server(self, name: str, await_release: bool = False) -> None:
        """关闭某个客户端的用户端口监听。

        ★ 默认只 close()，**不等** wait_closed()：
        用户端口上可能还挂着在途的用户连接（它们要等隧道配对），
        此时 wait_closed() 会一直等到那些连接关闭才返回 ——
        在有活跃连接时表现为长期悬挂。

        但有一个例外：证书热加载要**立刻在同一个端口上重建**监听，
        这时必须等旧监听口真正释放端口，否则可能 rebind 失败。
        所以那个场景传 await_release=True（带超时，避免被在途连接拖死）。
        """
        server = self._user_servers.pop(name, None)
        task = self._user_server_tasks.pop(name, None)
        if server is not None:
            server.close()
            if await_release:
                # 关掉所有已接受的连接，wait_closed() 才能尽快返回
                with contextlib.suppress(Exception, asyncio.TimeoutError):
                    await asyncio.wait_for(server.wait_closed(), timeout=2.0)
        await cancel_task(task)

    async def _on_tunnel_ready(self, reader, writer) -> None:
        """隧道连接：读名字 → 找到对应 Session → 与排队中的用户配对。"""
        try:
            name = await read_tunnel_ack(reader)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                ConnectionError, OSError) as exc:
            logger.warning("读取隧道标识失败: %s", exc)
            await close_writer(writer)
            return

        session = self.sessions.get(name)
        user = session.take_user() if session else None
        if user is None:
            logger.warning("[%s] 收到隧道但没有等待的用户（Session 存在=%s），丢弃",
                           name, session is not None)
            await close_writer(writer)
            return

        user_reader, user_writer = user.reader, user.writer
        # 通知 handle_user："这条连接我接管了"，它好回收限流计数并退出等待。
        # 必须在开始转发**之前**置位，避免用户侧等待超时而误关连接。
        user.taken.set()
        self.limiter.dequeue()

        if not self.limiter.active_acquire():
            self.stats.rejected_overload += 1
            logger.warning("[%s] 并发转发已达上限 %d，拒绝本次隧道",
                           name, self.limiter.max_active)
            await close_writer(user_writer)
            await close_writer(writer)
            return

        self.stats.tunnels_established += 1
        self.stats.connections_active += 1
        logger.info("[%s] 隧道建立，开始转发数据（%s）", name, self.limiter.snapshot)
        try:
            await asyncio.gather(
                stream_copy(user_reader, writer, f"{name}:用户→内网", self.stats,
                            idle_timeout=DATA_IDLE_TIMEOUT),
                stream_copy(reader, user_writer, f"{name}:内网→用户", self.stats,
                            idle_timeout=DATA_IDLE_TIMEOUT),
            )
        finally:
            self.stats.connections_active -= 1
            self.limiter.active_release()
            logger.info("[%s] 隧道关闭（%s）", name, self.limiter.snapshot)

    # ------------------------------------------------------------------
    # P2P 打洞
    # ------------------------------------------------------------------
    async def _ensure_p2p_listener(self) -> None:
        """在 UDP 上开一个打洞接收口（与 serve_port 同号）。

        为什么开在 serve_port 的 UDP 上？
            客户端已经知道 serve_host/serve_port，不用再多配一个端口。
            TCP 8800 与 UDP 8800 是两个独立名字空间，互不冲突。

        ★ 这个口只负责"让客户端的探测包能打到、并被回应"，从而把
          两边 NAT 上的映射撞开。本身不承载业务数据。
        """
        if not self.cfg("enable_p2p", True):
            logger.info("P2P 打洞已禁用（enable_p2p = false）")
            return
        port = self.cfg("serve_port", 7000)
        loop = asyncio.get_running_loop()
        frps = self

        class _P2PProto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                frps._on_p2p_datagram(data, addr)

        try:
            transport, _ = await loop.create_datagram_endpoint(
                _P2PProto, local_addr=(self.cfg("serve_host", "0.0.0.0"), port)
            )
        except OSError as exc:
            logger.warning("P2P 打洞口无法监听 UDP %s:%d: %s（打洞功能将不可用）",
                           self.cfg("serve_host", "0.0.0.0"), port, exc)
            return

        self._p2p_transport = transport
        self.p2p_udp_port = port
        logger.info("P2P 打洞口已监听 UDP %s:%d（客户端可尝试直连探测）",
                    self.cfg("serve_host", "0.0.0.0"), port)

    def _on_p2p_datagram(self, data: bytes, addr) -> None:
        """处理客户端发来的打洞探测包：原样把洞撞开并回应。"""
        from protocol import P2P_PROBE, encode_p2p_ready
        if not data or data[:1] != P2P_PROBE:
            return
        token = data[1:1 + P2P_TOKEN_SIZE]
        if token != self.p2p_token:
            # token 不对 —— 不是我们的客户端，忽略
            return
        if self._p2p_transport is not None:
            with contextlib.suppress(Exception):
                self._p2p_transport.sendto(encode_p2p_ready(token), addr)
        logger.debug("P2P 探测来自 %s，已回应（洞已撞开）", addr)

    def _stop_p2p_listener(self) -> None:
        if self._p2p_transport is not None:
            with contextlib.suppress(Exception):
                self._p2p_transport.close()
            self._p2p_transport = None

    # ------------------------------------------------------------------
    # UDP 转发
    # ------------------------------------------------------------------
    async def _ensure_udp_port(self, name: str, udp_port: int) -> None:
        """为某个客户端开（或复用）UDP 对外监听口。

        为什么 UDP 端口要和 TCP 端口分开？
            两者名字空间独立：TCP 9001 和 UDP 9001 互不冲突。
            客户端分别声明 tcp_port / udp_port，服务端各开各的。
            通常配成同一个数字（如都 9001），对外看起来就是"同一个服务"。
        """
        frontend = self._udp_frontends.get(name)
        if frontend is not None:
            if frontend.remote_port == udp_port:
                logger.info("[%s] 复用已存在的 UDP 端口 %d", name, udp_port)
                return
            logger.info("[%s] UDP 端口由 %s 变更为 %d，重建监听",
                        name, frontend.remote_port, udp_port)
            self._stop_udp_port(name)

        # 内网目标：默认由 frpc 用自身 local_host/local_port 决定，
        # 这里只需告诉它"这个客户端要 UDP"。target_port 用 0 占位，
        # 表示"由 frpc 自行决定"（因为服务端并不一定知道内网细节）。
        frontend = UdpFrontend(self, name, udp_port,
                               target_port=0,
                               target_addr=self.cfg("udp_target_addr", ""))

        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: frontend,
                local_addr=(self.cfg("user_host", "0.0.0.0"), udp_port),
            )
        except OSError as exc:
            logger.error("[%s] 无法监听 UDP 端口 %d: %s（可能被占用）",
                         name, udp_port, exc)
            return

        self._udp_frontends[name] = frontend
        self._udp_transports[name] = transport
        logger.info("[%s] UDP 端口已监听 %s:%d", name,
                    self.cfg("user_host", "0.0.0.0"), udp_port)

    def _stop_udp_port(self, name: str) -> None:
        """关闭 UDP 对外监听口（同时回收其所有会话）。"""
        frontend = self._udp_frontends.pop(name, None)
        transport = self._udp_transports.pop(name, None)
        if frontend is not None:
            frontend.close_all()
        if transport is not None:
            transport.close()

    async def _on_udp_tunnel(self, reader, writer) -> None:
        """UDP 隧道连接：客户端为"承载多路 UDP 会话"专门开的一条长连接。

        与控制/普通隧道不同的地方：
            普通隧道是"服务端有用户 → 通知客户端开隧道 → 一配一用完即弃"。
            UDP 隧道是"客户端接入时就预先开好一条常驻隧道"，之后所有
            外部 UDP 会话都复用这一条 —— 因为会话是动态冒出来的，
            来不及"先通知再建连"。
        """
        try:
            name = await read_tunnel_ack(reader)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                ConnectionError, OSError) as exc:
            logger.warning("读取 UDP 隧道标识失败: %s", exc)
            await close_writer(writer)
            return

        # 旧隧道（客户端重连时）先踢掉
        old = self.udp_tunnels.pop(name, None)
        if old is not None:
            await close_writer(old)

        self.udp_tunnels[name] = writer
        self._udp_warned.pop(name, None)
        logger.info("[%s] UDP 隧道已建立（会话将复用此通道）", name)

        # 隧道存续期间只做一件事：读 frpc 回来的 UDP_DATA / UDP_CLOSE。
        try:
            await self._udp_tunnel_loop(name, reader, writer)
        finally:
            if self.udp_tunnels.get(name) is writer:
                self.udp_tunnels.pop(name, None)
            frontend = self._udp_frontends.get(name)
            if frontend is not None:
                frontend.close_all()
            await close_writer(writer)
            logger.info("[%s] UDP 隧道已关闭", name)

    async def _udp_tunnel_loop(self, name: str, reader, writer) -> None:
        """读隧道里 frpc 发回来的帧，把 UDP 数据报投递给外部来源地址。"""
        frontend = self._udp_frontends.get(name)
        while True:
            cmd = await read_cmd(reader)
            if not cmd:
                logger.info("[%s] UDP 隧道对端已关闭", name)
                return
            if cmd == UDP_DATA:
                try:
                    session_id, payload = await read_udp_data(reader)
                except (asyncio.IncompleteReadError, ConnectionError, OSError,
                        ValueError) as exc:
                    logger.debug("[%s] 读取 UDP_DATA 出错: %s", name, exc)
                    return
                if frontend is None:
                    continue
                session = frontend.by_id.get(session_id)
                if session is None or session.closed:
                    continue
                try:
                    session.transport.sendto(payload, session.peer)
                    self.stats.udp_datagrams += 1
                    self.stats.udp_bytes += len(payload)
                except Exception as exc:
                    logger.debug("[%s] 回送 UDP 数据报失败: %s", name, exc)
            elif cmd == UDP_CLOSE:
                try:
                    raw = await reader.readexactly(SESSION_ID_SIZE)
                except (asyncio.IncompleteReadError, ConnectionError, OSError):
                    return
                session_id = decode_udp_close(raw)
                if frontend is not None:
                    frontend.close_session(session_id, notify=False)
            else:
                logger.debug("[%s] UDP 隧道收到未知帧 %r，忽略", name, cmd)

    async def _drop_udp(self, name: str) -> None:
        """客户端离线时，把它所有 UDP 资源（监听口、隧道、会话）清干净。"""
        self._stop_udp_port(name)
        writer = self.udp_tunnels.pop(name, None)
        if writer is not None:
            await close_writer(writer)
        self._udp_warned.pop(name, None)

    # ------------------------------------------------------------------
    # 面向外部用户的连接
    # ------------------------------------------------------------------
    async def handle_user(self, name: str, reader, writer) -> None:
        """外部用户接入某个客户端的端口：限流 → 排队 → 通知该客户端。"""
        peer_ip = self._peer_ip(writer)
        self.stats.connections_accepted += 1

        session = self.sessions.get(name)
        if session is None or session.closed:
            self.stats.rejected_offline += 1
            logger.warning("[%s] 客户端不在线，拒绝用户连接 %s", name, peer_ip)
            await close_writer(writer)
            return

        # 限流：这个客户端自己的单 IP 上限
        if not session.ip_acquire(peer_ip):
            self.stats.rejected_overload += 1
            logger.warning("[%s] 来源 %s 连接数已达上限 %d，拒绝",
                           name, peer_ip, session.max_per_ip)
            await close_writer(writer)
            return

        # 限流：全局队列上限
        if not self.limiter.enqueue():
            self.stats.rejected_overload += 1
            session.ip_release(peer_ip)
            logger.warning("[%s] 等待队列已满（%d），拒绝 %s",
                           name, self.limiter.max_queued, peer_ip)
            await close_writer(writer)
            return

        logger.info("[%s] 用户接入 %s，排队等待隧道（%s）",
                    name, peer_ip, self.limiter.snapshot)
        user = PendingUser(reader, writer)
        try:
            await session.pending_users.put(user)
            if not await session.notify_new_user():
                raise ConnectionError("通知客户端失败")
            await self._wait_until_served(name, user, peer_ip, session)
        except asyncio.CancelledError:
            self.limiter.dequeue()
            session.ip_release(peer_ip)
            raise
        except Exception as exc:
            self.limiter.dequeue()
            session.ip_release(peer_ip)
            logger.debug("[%s] 用户连接处理结束: %s", name, exc)

    async def _wait_until_served(self, name, user: "PendingUser",
                                 peer_ip, session) -> None:
        """等这条用户连接被隧道接管；一直没被接管（客户端忙/离线）才超时断开。

        ★ 关键：这里**绝不读取用户数据**，否则会吞掉首字节。
          判据是"隧道是否已接管"（user.taken），而不是"用户是否发来了数据"。
        """
        try:
            await asyncio.wait_for(user.taken.wait(), timeout=USER_CONN_TIMEOUT)
        except asyncio.TimeoutError:
            self.stats.rejected_timeout += 1
            logger.warning("[%s] 用户连接 %s 排队超时（无空闲隧道，%ds），断开",
                           name, peer_ip, USER_CONN_TIMEOUT)
            self.limiter.dequeue()
            session.ip_release(peer_ip)
            await close_writer(user.writer)
            return
        # 已被隧道接管：此时连接的所有权交给 _on_tunnel_ready，
        # 由它负责转发与关闭；这里只回收限流计数，不碰 writer。
        self.limiter.dequeue()
        session.ip_release(peer_ip)

    @staticmethod
    def _peer_ip(writer) -> str:
        peername = writer.get_extra_info("peername")
        return peername[0] if peername else "unknown"

    # ------------------------------------------------------------------
    # 证书热加载（自动续期后调用）
    # ------------------------------------------------------------------
    async def reload_certificates(self) -> None:
        """用新证书重建 SSLContext，并让所有监听口换用新上下文。

        ★ 为什么必须「重启监听口」而不能只改属性？

        实测发现（CPython 3.13，见 base_events.py 的 Server._start_serving）：
            asyncio 在 start_serving() 时就把当时的 ssl_context **固化**进了
            每个 socket 对应的 protocol factory。之后再改 Server._ssl_context，
            新连接依然用旧上下文 —— 表现为"续期成功了，但客户端还是报
            certificate signature failure"。

        所以正确做法是：关掉旧监听口 → 用新 ctx 重新 start_server。
        客户端此时会短暂断连，但它们都有自动重连（5 秒），很快会恢复。
        """
        if not (self.cfg("cert_file") and self.cfg("key_file")):
            return
        try:
            self.ssl_ctx = build_server_ssl_context(
                self.cfg("cert_file"), self.cfg("key_file")
            )
        except Exception as exc:
            logger.error("重新加载证书失败，继续使用旧证书: %s", exc)
            return

        # 记住每个客户端的名字和端口，重建时用
        rebuild = []
        for name, server in list(self._user_servers.items()):
            port = self._server_port(server)
            if port:
                rebuild.append((name, port))

        logger.info("证书已更新，正在重建 %d 个用户端口监听……", len(rebuild))
        for name, port in rebuild:
            # 这一路需要"等旧端口释放"，好让新监听能绑上同一个端口
            await self._stop_user_server(name, await_release=True)
            await self._ensure_user_port(name, port)

        self.stats.cert_renewals += 1
        logger.info("证书热加载完成，新连接将使用新证书")

    # ------------------------------------------------------------------
    # 启动 / 重启
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """启动控制端口，保持常驻，并拉起统计与证书检查的后台任务。"""
        if self.ssl_ctx is None:
            logger.warning("未配置 TLS 证书，本次为明文传输（生产环境请务必启用 TLS）")
        if not self.tokens.tokens:
            logger.error("没有可用的 token，服务端无法接受任何客户端")

        left = cert_days_left(self.cfg("cert_file")) if self.cfg("cert_file") else None
        if left is not None:
            logger.info("当前证书剩余 %.1f 天", left)

        # 后台任务统一放一个列表，退出时逐个取消并**等待**它们真正结束。
        # ★ 只 cancel() 不 await 是不行的：任务可能还卡在（如 wait_for）内部，
        #   cancel 之后要等事件循环调度到它才会真正退出；
        #   而且一个"未回收的待取消任务"会让外层 gather 一直等下去 ——
        #   实测表现为"teardown 已完成，但 cancel 后 10 秒才返回"。
        background = [
            asyncio.create_task(self._periodic_stats()),
            asyncio.create_task(self._token_watch()),
            asyncio.create_task(self._cert_watch()),
        ]
        # 打开 P2P 打洞 UDP 接收口（在进入监听循环前一次）
        await self._ensure_p2p_listener()
        try:
            while True:
                conn_tasks: "dict[asyncio.Task, None]" = {}
                frp_server = None
                try:
                    frp_server = await asyncio.start_server(
                        self._spawn_conntrack(self.handle_frpc, conn_tasks),
                        host=self.cfg("serve_host", "0.0.0.0"), port=self.cfg("serve_port", 7000),
                        ssl=self.ssl_ctx,
                    )
                    logger.info("控制端口监听 %s:%s%s（供内网客户端连接）",
                                self.cfg("serve_host", "0.0.0.0"), self.cfg("serve_port", 7000),
                                " [TLS]" if self.ssl_ctx else " [明文]")
                    logger.info("用户端口将按客户端注册动态开启（等待客户端接入）")

                    # ★★ 这里**刻意不用** frp_server.serve_forever() ★★
                    #   实测踩坑（CPython 3.13 + Windows Proactor）：
                    #   serve_forever() 源码在收到 CancelledError 时会执行
                    #       self.close(); await self.wait_closed()
                    #   而 wait_closed() 必须等**所有连接**都关闭才返回；
                    #   Windows 上只要还有一个活跃连接（如 frpc 控制长连接），
                    #   它就会**永久悬挂**。
                    #   于是形成死锁：取消 → serve_forever → 等连接关 →
                    #   而"关连接"这件事在 _teardown 里，_teardown 又排在
                    #   serve_forever() **返回之后**，永远轮不到。
                    #   症状：cancel() 后任务 cancelling()==1 但迟迟不结束，
                    #        要等客户端自己掉线（连接关闭）才解开。
                    #   解法：用一个普通的、可被立刻取消的等待代替它；
                    #        监听口的关闭与连接回收，全部由 _teardown 负责。
                    await self._idle_forever()
                    logger.error("监听已停止，%s 秒后重启", RECONNECT_INTERVAL)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.error("服务端异常: %s，%s 秒后重启", exc, RECONNECT_INTERVAL)
                finally:
                    # ★ 清理必须放在 finally 里。
                    #   不要在 except asyncio.CancelledError 里 await 清理动作 ——
                    #   一旦在取消分支里 await，Python 会认为"取消已被处理"，
                    #   取消状态被吞掉，任务变成"永不结束的僵尸"。
                    await self._teardown(frp_server, conn_tasks)
                await asyncio.sleep(RECONNECT_INTERVAL)
        finally:
            for t in background:
                await cancel_task(t)
            self._stop_p2p_listener()

    @staticmethod
    async def _idle_forever() -> None:
        """一个"什么都不做、但能被立刻取消"的常驻等待。

        为什么不用 serve_forever()？见 start() 里的详细注释：
        它在 Windows 上取消时会因 wait_closed() 而永久悬挂。
        这里用一个永不 set 的 Event 代替 —— 取消它没有任何副作用。
        """
        await asyncio.Event().wait()

    async def _periodic_stats(self) -> None:
        """每 60 秒打印一次运行摘要。"""
        while True:
            await asyncio.sleep(60)
            online = ",".join(self.sessions.keys()) or "无"
            logger.info("统计 | 在线客户端[%s] | %s", online, self.stats.summary())

    async def _token_watch(self) -> None:
        """定期检查 token 文件是否有变化，变了就热重载（支持 token 轮换）。"""
        if not self.cfg("token_file"):
            return
        while True:
            await asyncio.sleep(5)
            self.tokens.reload_from_file()

    async def _cert_watch(self) -> None:
        """启动时检查一次 + 运行中每天检查，临期自动续期并热加载。"""
        if not (self.cfg("cert_file") and self.cfg("key_file")):
            return

        # --- 启动时检查 ---
        # 注意这里**不**在启动阶段重建监听口：此时监听口还没建立起来，
        # 重建是空操作，真正该做的是在监听口建好之后再热加载一次。
        # 用 wait_for 包一层，避免续期逻辑里的同步阻塞把取消信号拖住。
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    ensure_valid_cert,
                    self.cfg("cert_file"), self.cfg("key_file"),
                    self.cfg("ca_cert_file", ""), self.cfg("ca_key_file", ""),
                    self.cfg("cert_host") or None,
                    self.cfg("cert_renew_days", 30),
                ),
                timeout=60,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("启动时证书检查失败: %s", exc)

        # 启动时的续期发生在监听口建立**之前**，所以那时没有端口可换。
        # 但也不能像早先那样"等端口一建就重建端口" —— 实测踩坑：
        #   第一个客户端刚接入、用户端口刚监听成功，就被无条件关掉重建，
        #   导致排在旧监听口队列里的外部连接全部丢失（外部读到空数据），
        #   同时把该客户端的隧道连接打断（日志表现为"已断开，等待重连"）。
        # 正确做法：这里只需**用新证书重建 SSLContext**（不碰任何监听口），
        # 之后新建的用户端口自然会用上它。
        self._refresh_ssl_context()

        # --- 运行中周期检查 ---
        await cert_renew_loop(
            self.cfg("cert_file"), self.cfg("key_file"),
            self.cfg("ca_cert_file", ""), self.cfg("ca_key_file", ""),
            hosts=self.cfg("cert_host") or ["localhost"],
            on_renewed=self.reload_certificates,
            threshold_days=self.cfg("cert_renew_days", 30),
            stats=self.stats,
        )

    def _refresh_ssl_context(self) -> bool:
        """只重建 SSLContext，不动任何监听口。

        适用于"监听口尚未建立"的启动阶段：此时用新 ctx 直接建端口即可，
        既省掉一次无谓的端口重建，也不会打断任何在途连接。
        """
        if not (self.cfg("cert_file") and self.cfg("key_file")):
            return False
        try:
            self.ssl_ctx = build_server_ssl_context(
                self.cfg("cert_file"), self.cfg("key_file")
            )
            return True
        except Exception as exc:
            logger.error("重建 SSLContext 失败，继续用旧证书: %s", exc)
            return False

    async def _teardown(self, frp_server, conn_tasks) -> None:
        """关闭所有监听口 + 回收所有在途任务。

        ★ 顺序与超时都很关键（在 Windows 上实测踩过的坑）：
        必须先取消在途连接任务，再 await server.wait_closed() ——
        CPython 的 wait_closed() 要等所有连接都关掉才返回，
        Windows 上还有活跃连接时会永久悬挂。
        """
        # 1) 停收新连接（控制端口 + 所有用户端口）
        if frp_server is not None:
            frp_server.close()
        for name in list(self._user_servers.keys()):
            await self._stop_user_server(name)
        # 1b) 停掉所有 UDP 监听口与隧道
        for name in list(self._udp_frontends.keys()):
            self._stop_udp_port(name)
        for name in list(self.udp_tunnels.keys()):
            writer = self.udp_tunnels.pop(name, None)
            if writer is not None:
                await close_writer(writer)

        # 2) 先取消并等待所有在途连接任务（此刻连接才真正关闭）
        await self._wait_tasks(conn_tasks)
        for name in list(self._session_tasks.keys()):
            task = self._session_tasks.pop(name, None)
            await cancel_task(task)
        # 同步清空多客户端登记表，避免残留引用
        self.sessions.clear()

        # 3) 连接都关了，wait_closed() 才能立刻返回；加超时兜底
        if frp_server is not None:
            with contextlib.suppress(Exception, asyncio.TimeoutError):
                await asyncio.wait_for(frp_server.wait_closed(), timeout=1.0)
        # 4) 关掉 P2P 打洞口（每轮重启都要重新建，避免端口占用）
        self._stop_p2p_listener()

    def _spawn_conntrack(self, handler, conn_tasks):
        """把 handler 包一层，登记成可追踪的任务（便于退出时统一取消）。"""
        async def wrapper(reader, writer):
            task = asyncio.current_task()
            conn_tasks[task] = None
            try:
                await handler(reader, writer)
            finally:
                conn_tasks.pop(task, None)
        return wrapper

    @staticmethod
    def _spawn(handler):
        """给用户端口用的轻量包装：只登记，不追踪（用户端口生命周期随 Session）。"""
        async def wrapper(reader, writer):
            try:
                await handler(reader, writer)
            except Exception as exc:
                logger.debug("用户连接处理异常: %s", exc)
        return wrapper

    @staticmethod
    async def _wait_tasks(conn_tasks) -> None:
        """取消并回收一组在途连接任务（每个都带超时，避免个别赖着不走）。"""
        tasks = [t for t in conn_tasks if not t.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True), timeout=5.0
                )


async def main(args) -> None:
    frps = Frps(args)
    await frps.start()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="FRP 服务端（多客户端 / token 轮换 / 证书自动续期）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # 网络
    parser.add_argument("--serve_host", default="0.0.0.0", help="供内网客户端连接的主机")
    parser.add_argument("--serve_port", type=int, default=8800, help="供内网客户端连接的端口")
    parser.add_argument("--user_host", default="0.0.0.0", help="对外服务监听地址（各客户端共用）")
    # 安全
    parser.add_argument("--token", default="",
                        help="共享密钥；多个用逗号分隔可实现新旧并存的轮换过渡期")
    parser.add_argument("--token_file", default="",
                        help="从文件读取 token（每行一个，# 为注释，首行为主 token）；支持热重载")
    parser.add_argument("--cert_file", default="", help="服务端证书（启用 TLS）")
    parser.add_argument("--key_file", default="", help="服务端私钥（启用 TLS）")
    parser.add_argument("--ca_cert_file", default="", help="CA 根证书（自动续期用）")
    parser.add_argument("--ca_key_file", default="", help="CA 私钥（自动续期用）")
    parser.add_argument("--cert_host", action="append", default=[],
                        help="续期时写入证书的 IP/域名，可重复；不填则沿用 localhost")
    parser.add_argument("--cert_renew_days", type=int, default=30,
                        help="证书剩余少于该天数时自动续期")
    # 限流
    parser.add_argument("--max_conn_per_ip", type=int, default=20,
                        help="单 IP 对**单个客户端**的最大并发连接数")
    parser.add_argument("--max_active_conns", type=int, default=100,
                        help="全局最大并发转发连接数")
    parser.add_argument("--max_queued", type=int, default=50,
                        help="等待队列最大长度")
    # UDP
    parser.add_argument("--udp_target_addr", default="",
                        help="UDP 内网目标地址（一般留空，由客户端用它自己的 local_host）")
    parser.add_argument("--max_udp_sessions", type=int, default=512,
                        help="单客户端最大并发 UDP 会话数（按外部来源地址计）")
    parser.add_argument("--udp_session_timeout", type=int, default=60,
                        help="UDP 会话空闲多少秒后回收")
    # P2P
    parser.add_argument("--no_p2p", dest="enable_p2p", action="store_false",
                        default=True,
                        help="关闭 P2P 打洞探测（默认开启，只走中转时用）")
    # 日志
    parser.add_argument("--log_level", default="INFO",
                        help="日志级别 DEBUG/INFO/WARNING/ERROR")
    # 作者信息
    parser.add_argument("--about", action="store_true",
                        help="显示程序与作者信息后退出")
    # 配置文件（极简调用：python frps.py -c server.toml）
    add_common_args(parser)
    remember_defaults(parser)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.about:                  # --about：只打印信息，不启动服务
        print(about.summary())
        for _k, _v in about.author_lines():
            print("  %s：%s" % (_k, _v))
        raise SystemExit(0)
    attach_config(args, logger)     # 套用配置文件（命令行优先）

    if not args.token and not args.token_file:
        logger.error("必须通过 --token / --token_file 指定共享密钥（或在配置文件里配 token）")
        raise SystemExit(2)
    if bool(args.cert_file) != bool(args.key_file):
        logger.error("--cert_file 与 --key_file 必须同时提供，或同时省略")
        raise SystemExit(2)
    # token_file 只在文件不存在时才算问题；token 直接给字符串则不检查
    if args.token_file and not args.token and not os.path.exists(args.token_file):
        logger.error("token 文件不存在：%s", args.token_file)
        raise SystemExit(2)

    logger.setLevel(parse_log_level(args.log_level))
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        logger.info("已手动退出")
