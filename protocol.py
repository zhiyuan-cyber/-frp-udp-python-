"""
protocol.py —— frpc / frps 两端共用的"协议层"

为什么要单独抽一个文件？
    原来的 frpc.py 和 frps.py 里各写了一份一模一样的 stream_copy，
    而且满篇是 b'1' / b'2' 这种"魔法字节"，看代码的人必须靠猜才知道
    它们代表什么。这里把「协议常量」「鉴权握手」「TLS 上下文」「统计」
    「通用工具」集中到一处，两端 import 同一份，改一处即可。

──────────────────────────── 协议概览 ────────────────────────────

  控制通道（frpc 主动连 frps 的 serve_port）：

      frps ──▶ frpc   AUTH_CHALLENGE + 32 字节随机数      "证明你的身份"
      frpc ──▶ frps   AUTH_RESPONSE  + 32 字节 HMAC 摘要    "这是我的应答"
      frps ──▶ frpc   AUTH_OK / AUTH_FAIL                  握手结果

      鉴权通过后，客户端立刻上报自己的身份（名字 + 声明的对外端口）：

      frpc ──▶ frps   REGISTER + [1字节名字长度][名字][2字节端口]

      然后双方在该连接上跑心跳：

      frpc ──▶ frps   PING      frps ──▶ frpc   PING

  数据隧道（frpc 为每个新用户新建一条连接）：

      frps ──▶ frpc   TUNNEL_REQ + 客户端名字（frps 知道该找谁）
      frpc ──▶ frps   TUNNEL_ACK + 客户端名字（服务端据此路由到对应 Session）

  简单说：TCP 是"一条连接 = 一条隧道"，用完即弃。

──────────────────────────── UDP 转发概览 ────────────────────────────

  UDP 为什么不能照搬 TCP 的做法？
      TCP 是"连接"：每个外部用户各自一条 TCP，天然一一对应，
      所以可以"每条 TCP 连接开一条隧道"。
      但 UDP 是"数据报"：没有连接概念，同一个客户端的一串包可能
      从同一个源地址源源不断发来，中间还可能夹杂其他用户的包。
      如果每个包都开一条隧道，开销会爆炸；而且 UDP 服务端看到的是
      "每条隧道一个源端口"，会话状态就乱了。

  解决办法：**一条 UDP 隧道承载多路会话，用会话 ID 分流**。

      · 隧道本身仍然是 TCP（复用现成的 TLS + 鉴权 + 心跳），
        只是隧道里跑的不是"裸字节流"，而是"带会话头的帧"。
      · 每来一个新的外部源地址（IP+端口），就分配一个 session_id，
        同一源地址后续的包继续用这个 session_id。
      · frpc 侧对每个 session_id 持有一个"本机 UDP 套接字"，用同一个
        套接字收发，于是 UDP 服务端看到的源端口是稳定的 —— 会话不散。

  帧格式（隧道内的字节流，全部大端）：

      UDP_ASSOC  （frps → frpc）分配/确认一路 UDP 会话：
          长度: 1B cmd + 4B session_id + 2B 目标端口 + (1B addr 长度 + addr)
          说明：addr 是"内网目标地址"，默认取 frpc 配置的 local_host，
                通常留空；留空时 frpc 用自己的 local_host/local_port。

      UDP_DATA   （双向）一个 UDP 数据报：
          长度: 1B cmd + 4B session_id + 4B payload 长度 + payload
          说明：长度字段必须有 —— UDP 是"消息边界敏感"的，
                TCP 流的天然切分点不能当作 UDP 报文边界。

      UDP_CLOSE  （双向）关闭一路会话：
          长度: 1B cmd + 4B session_id

      UDP_PING/… 不需要单独设计心跳：外层 TCP 隧道已有 PING 保活，
                只要隧道活着，会话就活着；隧道断了会整体重连。
"""

import asyncio
import contextlib
import hashlib
import hmac
import logging
import os
import ssl
import struct
import time

logger = logging.getLogger("frp.protocol")

# ---------------------------------------------------------------------------
# 协议常量
# ---------------------------------------------------------------------------

PING = b"1"             # 心跳
TUNNEL_REQ = b"2"       # 请求开隧道：服务端 → 客户端
TUNNEL_ACK = b"3"       # 隧道握手：客户端 → 服务端

AUTH_CHALLENGE = b"A"   # 鉴权挑战：服务端 → 客户端
AUTH_RESPONSE = b"B"    # 鉴权应答：客户端 → 服务端
AUTH_OK = b"K"          # 鉴权通过：服务端 → 客户端
AUTH_FAIL = b"F"        # 鉴权失败：服务端 → 客户端

REGISTER = b"R"         # 客户端上报身份：客户端 → 服务端

# --- UDP 转发相关 ---
UDP_TUNNEL = b"T"       # 声明"这是一条 UDP 承载隧道"：客户端 → 服务端
UDP_ASSOC = b"U"        # 分配/确认一路 UDP 会话：frps → frpc
UDP_DATA = b"D"         # 一个 UDP 数据报：双向
UDP_CLOSE = b"E"        # 关闭一路 UDP 会话：双向

# --- P2P 打洞（UDP 直连探测） ---
P2P_INFO = b"I"         # 打洞参数下发：服务端 → 客户端（共享 token + 服务端 UDP 端口）
P2P_PROBE = b"P"        # 打洞探测包：双向。双方互发，用来"在各自的 NAT 上开洞"
P2P_READY = b"Y"        # 打洞成功确认：收到并验证对方的探测后回复
P2P_RESULT = b"R"       # 打洞结果回报：客户端 → 服务端（成功/失败，便于服务端统计）
CMD_SIZE = 1            # 指令长度固定 1 字节
NONCE_SIZE = 32         # 挑战随机数长度（字节）
DIGEST_SIZE = 32        # HMAC-SHA256 摘要长度（字节）
NAME_SIZE = 1           # 客户端名字长度字段：1 字节（上限 255 字符）
PORT_SIZE = 2           # 端口字段：2 字节大端（0-65535）

# UDP 会话 ID：4 字节大端。用 32 位是为了在长时间运行、会话频繁
# 建立/回收的场景下也不容易回绕冲突。
SESSION_ID_SIZE = 4
# UDP 报文长度字段：4 字节大端（单包上限 4 GiB，实际受 UDP 本身限制）
UDP_LEN_SIZE = 4
# 单个 UDP 数据报允许的最大长度。UDP 本身建议不超过 MTU（约 1472 字节），
# 但考虑到隧道是 TCP、且实际可能有人传大包，这里给一个宽松上限做保护。
MAX_UDP_PAYLOAD = 2 ** 16

MAX_NAME_LEN = 255

# UDP 会话空闲多久回收（秒）。UDP 没有"关闭"语义，只能靠空闲超时判断会话结束。
UDP_SESSION_TIMEOUT = 60

# ---------------------------------------------------------------------------
# 可调参数
# ---------------------------------------------------------------------------

# 单次读写的数据块大小：64 KiB。
# 太小 → 系统调用次数多，吞吐低；太大 → 单连接内存占用高。
CHUNK_SIZE = 2 ** 16

# 心跳间隔（秒）。必须远小于 NAT / 防火墙的空闲连接超时（通常几分钟）。
# ★ 这个值同时决定"多久没收到对端任何字节就判定假死"：见 HEARTBEAT_TIMEOUT。
HEARTBEAT_INTERVAL = 10

# 心跳宽限期：连续多久收不到对端的任何字节，就判定这条连接已死。
# 取 3 倍心跳间隔 —— 允许偶发丢 1~2 个心跳包，又能在 30 秒内识破"TCP 半开
# "（连接看起来还在，实际对端/中间设备早已消失）。
HEARTBEAT_TIMEOUT = HEARTBEAT_INTERVAL * 3

# 隧道连接的空闲保活间隔（秒）。数据隧道在空闲时也定期发一个字节，
# 避免被中间 NAT / 防火墙按"空闲连接"静默回收。设得比心跳长，
# 因为隧道是有真实数据的，只有长时间空闲才需要保活。
TUNNEL_IDLE_PING = 60

# 数据隧道的"空闲判死"阈值（秒）。
# ★ 数据隧道不能注入心跳字节（会污染用户数据流），所以只能用
#   "多久没读到数据"来判断连接是否已经假死。
#   取一个宽松的值：既能兜住 TCP 半开，又不会误杀"长期安静"的合法连接
#   （比如某些挂着不动的长连接）。
DATA_IDLE_TIMEOUT = 300

# 重连退避：首次失败后等 RECONNECT_INTERVAL，每连续失败一次翻倍，
# 上限 RECONNECT_MAX_INTERVAL。这样"抖动"能快速恢复，
# "服务端长期宕机"也不会让成百上千个客户端每秒狂敲服务端。
RECONNECT_INTERVAL = 5
RECONNECT_MAX_INTERVAL = 60

# 重连退避的随机抖动比例（0~1）。让多个客户端不要在同一时刻齐步重连。
RECONNECT_JITTER = 0.3

# 握手（鉴权 + 注册）超时：防止恶意连接占着不放。
HANDSHAKE_TIMEOUT = 10

# 用户连接在队列里等待被服务的最长时间（秒），超时即断开。
USER_CONN_TIMEOUT = 30


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """创建一个格式统一的 logger，便于排查问题。

    异步程序一旦并发量上来，print 出来的输出会互相穿插、无法定位，
    所以统一走 logging，并在日志里带上时间、级别、模块名。
    """
    lg = logging.getLogger(name)
    if not lg.handlers:  # 避免被重复调用时叠加 handler，导致日志打两遍
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        lg.addHandler(handler)
        lg.propagate = False
    lg.setLevel(level)
    return lg


def parse_log_level(text: str) -> int:
    """把命令行里的 'debug' / 'info' 之类转成 logging 级别常量。"""
    level = getattr(logging, text.upper(), None)
    if not isinstance(level, int):
        raise ValueError(f"无效的日志级别: {text}")
    return level


# ---------------------------------------------------------------------------
# 鉴权：HMAC 挑战-应答（支持新旧 token 并存的过渡期）
# ---------------------------------------------------------------------------

def make_challenge() -> bytes:
    """生成一次性随机挑战值 (nonce)。"""
    return os.urandom(NONCE_SIZE)


def compute_digest(token: str, nonce: bytes) -> bytes:
    """用共享 token 对 nonce 做 HMAC-SHA256。

    为什么用挑战-应答，而不是"客户端直接把 token 发过去"？
        直接发 token 等于把口令明文放在链路上（即便有 TLS，日志/抓包也可能泄露）。
        挑战-应答模式下，链路上只出现一次性的随机值和它的摘要，
        攻击者拿到摘要也无法反推 token，更无法在另一次会话里复用（nonce 每次不同）。
    """
    return hmac.new(token.encode("utf-8"), nonce, hashlib.sha256).digest()


def parse_token_spec(value) -> "list[str]":
    """把各种"token 来源"的写法归一化成字符串列表。

    支持三种写法（配置文件和命令行都能用）：
        "a,b"          → ["a", "b"]        逗号分隔的字符串
        "a"            → ["a"]             单个
        ["a", "b"]     → ["a", "b"]        列表/元组（TOML 里写数组）
        ""/None/[]     → []                空

    为什么需要它？命令行只能给字符串，而 TOML 可以直接给数组，
    两者最终都要喂给 TokenStore，这里统一抹平差异。
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        # 列表元素本身也可能是 "a,b" 形式，进一步拆开
        out = []
        for item in value:
            out.extend(parse_token_spec(item))
        return out
    return [t for t in str(value).split(",") if t]


class TokenStore:
    """token 仓库，支持新旧两个 token 并存的"轮换过渡期"。

    轮换为什么需要过渡期？
        如果服务端只认新 token，那你一改配置，所有客户端立刻全部掉线，
        必须同时更新所有客户端才能恢复 —— 在有多台机器时这几乎做不到零中断。
        过渡期允许服务端同时接受 ["新 token", "旧 token"]：
            第 1 天：服务端换成新 token 列表，客户端还是旧的 → 仍能用；
            第 2 天：逐个把客户端换成新 token → 也没问题；
            第 N 天：确认所有客户端都换完，从列表里去掉旧 token → 轮换结束。
    """

    def __init__(self, tokens: "list[str] | None" = None, token_file: str = ""):
        # 过滤空字符串，避免 --token "" 之类的误配置变成"任何 token 都通过"
        self._tokens = [t for t in (tokens or []) if t]
        self.token_file = token_file
        self._file_mtime = 0.0
        if token_file:
            self.reload_from_file(force=True)

    @property
    def tokens(self) -> "list[str]":
        return list(self._tokens)

    @property
    def primary(self) -> str:
        """当前主 token（列表第一个）。客户端默认用它。"""
        return self._tokens[0] if self._tokens else ""

    def verify(self, digest: bytes, nonce: bytes) -> "str | None":
        """校验摘要是否匹配任一 token。匹配则返回命中的 token，否则 None。

        注意：必须对所有候选 token 都做一次恒定时间比较后再统一返回，
        不能在循环里"匹配到就 return" —— 那样能通过响应耗时推断出
        "第几个 token 匹配上了"，泄露轮换状态。
        """
        hit = None
        for token in self._tokens:
            if hmac.compare_digest(digest, compute_digest(token, nonce)):
                hit = token
        return hit

    def reload_from_file(self, force: bool = False) -> bool:
        """从文件重载 token（支持运行中热更新）。返回是否发生了变化。

        文件格式：每行一个 token，# 开头为注释，第一个非注释行是主 token。
        """
        if not self.token_file:
            return False
        try:
            st = os.stat(self.token_file)
        except OSError as exc:
            logger.error("无法读取 token 文件 %s: %s", self.token_file, exc)
            return False

        if not force and st.st_mtime == self._file_mtime:
            return False  # 文件没变，不必重读

        try:
            with open(self.token_file, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError as exc:
            logger.error("读取 token 文件失败: %s", exc)
            return False

        tokens = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                tokens.append(line)

        if not tokens:
            logger.error("token 文件 %s 里没有有效 token，保持原配置", self.token_file)
            return False

        self._file_mtime = st.st_mtime
        changed = tokens != self._tokens
        self._tokens = tokens
        if changed:
            logger.info("已从 %s 重载 token（当前共 %d 个，过渡期模式%s）",
                        self.token_file, len(tokens),
                        "开启" if len(tokens) > 1 else "关闭")
        return changed


async def server_authenticate(reader, writer, tokens: TokenStore) -> bool:
    """服务端侧：发挑战 → 校验客户端应答。返回是否通过。

    注意：所有读取都带超时，避免恶意客户端连上来后不发数据、白占一个协程。
    """
    nonce = make_challenge()
    writer.write(AUTH_CHALLENGE + nonce)
    await writer.drain()

    try:
        cmd = await asyncio.wait_for(reader.readexactly(CMD_SIZE), HANDSHAKE_TIMEOUT)
        if cmd != AUTH_RESPONSE:
            logger.warning("鉴权失败：客户端未按协议应答 (收到 %r)", cmd)
            return False
        digest = await asyncio.wait_for(
            reader.readexactly(DIGEST_SIZE), HANDSHAKE_TIMEOUT
        )
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
        logger.warning("鉴权失败：读取应答超时或连接中断")
        return False

    if tokens.verify(digest, nonce) is None:
        logger.warning("鉴权失败：token 不匹配")
        return False

    writer.write(AUTH_OK)
    await writer.drain()
    return True


async def client_authenticate(reader, writer, token: str) -> bool:
    """客户端侧：收挑战 → 发应答 → 看服务端是否放行。"""
    try:
        cmd = await asyncio.wait_for(reader.readexactly(CMD_SIZE), HANDSHAKE_TIMEOUT)
        if cmd != AUTH_CHALLENGE:
            logger.error("鉴权失败：服务端未发挑战 (收到 %r)", cmd)
            return False
        nonce = await asyncio.wait_for(
            reader.readexactly(NONCE_SIZE), HANDSHAKE_TIMEOUT
        )

        writer.write(AUTH_RESPONSE + compute_digest(token, nonce))
        await writer.drain()

        reply = await asyncio.wait_for(reader.readexactly(CMD_SIZE), HANDSHAKE_TIMEOUT)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
        logger.error("鉴权失败：握手超时或连接中断 (%s)", exc)
        return False

    if reply != AUTH_OK:
        logger.error("鉴权失败：服务端拒绝了本客户端（请检查 token 是否一致）")
        return False
    return True


# ---------------------------------------------------------------------------
# 客户端身份注册（多客户端路由的基础）
# ---------------------------------------------------------------------------

def encode_register(name: str, remote_port: int, udp_port: int = 0) -> bytes:
    """把 (名字, 对外端口, UDP 对外端口) 编码成注册报文。

    格式：REGISTER + [1B 名字长度][名字 UTF-8][2B TCP端口][2B UDP端口]

    ★ 兼容性设计：UDP 端口是后加的能力 —— 如果客户端根本不跑 UDP，
      它就不带这 2 个字节。服务端据此区分"老客户端"和"要 UDP 的客户端"，
      老客户端完全不受影响（不打补丁也能继续用）。
      udp_port = 0 表示"本客户端不需要 UDP 转发"。
    """
    raw = name.encode("utf-8")
    if len(raw) > MAX_NAME_LEN:
        raise ValueError(f"客户端名字过长（{len(raw)} > {MAX_NAME_LEN} 字节）")
    payload = REGISTER + struct.pack("!B", len(raw)) + raw + struct.pack("!H", remote_port)
    if udp_port:
        payload += struct.pack("!H", udp_port)
    return payload


def decode_register(payload: bytes) -> "tuple[str, int, int]":
    """解析注册报文（不含前导的 REGISTER 指令字节）。

    返回 (name, remote_port, udp_port)。udp_port 缺失时为 0。
    """
    if not payload:
        raise ValueError("注册报文为空")
    name_len = payload[0]
    if len(payload) < 1 + name_len + PORT_SIZE:
        raise ValueError("注册报文长度不足")
    name = payload[1:1 + name_len].decode("utf-8", errors="replace")
    base = 1 + name_len
    port = struct.unpack("!H", payload[base:base + PORT_SIZE])[0]
    udp_port = 0
    if len(payload) >= base + PORT_SIZE * 2:
        udp_port = struct.unpack(
            "!H", payload[base + PORT_SIZE:base + PORT_SIZE * 2]
        )[0]
    return name, port, udp_port


async def send_register(writer, name: str, remote_port: int, udp_port: int = 0) -> None:
    """客户端侧：上报自己的身份（含可选的 UDP 对外端口）。"""
    writer.write(encode_register(name, remote_port, udp_port))
    await writer.drain()


async def read_register(reader) -> "tuple[str, int, int]":
    """服务端侧：读取客户端身份。

    分几步读（长度 → 名字 → 端口 → 可选的 UDP 端口），每步都带超时，
    防止半截报文吊死协程。
    """
    head = await asyncio.wait_for(reader.readexactly(CMD_SIZE), HANDSHAKE_TIMEOUT)
    if head != REGISTER:
        raise ValueError(f"期望注册报文，收到 {head!r}")
    name_len = struct.unpack(
        "!B", await asyncio.wait_for(reader.readexactly(NAME_SIZE), HANDSHAKE_TIMEOUT)
    )[0]
    name = (
        await asyncio.wait_for(reader.readexactly(name_len), HANDSHAKE_TIMEOUT)
    ).decode("utf-8", errors="replace") if name_len else ""
    port = struct.unpack(
        "!H", await asyncio.wait_for(reader.readexactly(PORT_SIZE), HANDSHAKE_TIMEOUT)
    )[0]
    # UDP 端口是可选字段：尝试读，读不到（老客户端 / 对端已发完）就算没有。
    # ★ 不能直接 readexactly 然后容错为 0 —— 那样会把"老客户端"误判成
    #   "连接中断"。这里用一个短超时试探性读取，拿不到就当 0。
    udp_port = 0
    try:
        raw_udp = await asyncio.wait_for(
            reader.readexactly(PORT_SIZE), timeout=HANDSHAKE_TIMEOUT
        )
        udp_port = struct.unpack("!H", raw_udp)[0]
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        udp_port = 0
    return name, port, udp_port


async def send_tunnel_ack(writer, name: str) -> None:
    """客户端侧：声明"这条连接是给哪个客户端的隧道"。"""
    raw = name.encode("utf-8")[:MAX_NAME_LEN]
    writer.write(TUNNEL_ACK + struct.pack("!B", len(raw)) + raw)
    await writer.drain()


async def send_udp_tunnel_ack(writer, name: str) -> None:
    """客户端侧：声明"这条连接是本客户端的 UDP 承载隧道"。

    ★ 为什么必须和普通隧道用不同指令？
      否则服务端无法区分"一条给某个外部用户的 TCP 隧道"和
      "一条承载全部 UDP 会话的常驻隧道"，会把 UDP 隧道误配给排队的用户。
      区分开之后，两条路各走各的分支，互不干扰。
    """
    raw = name.encode("utf-8")[:MAX_NAME_LEN]
    writer.write(UDP_TUNNEL + struct.pack("!B", len(raw)) + raw)
    await writer.drain()


async def read_tunnel_ack(reader) -> str:
    """服务端侧：读取隧道声明的客户端名字，据此路由到对应 Session。"""
    name_len = struct.unpack(
        "!B", await asyncio.wait_for(reader.readexactly(NAME_SIZE), HANDSHAKE_TIMEOUT)
    )[0]
    if not name_len:
        return ""
    raw = await asyncio.wait_for(reader.readexactly(name_len), HANDSHAKE_TIMEOUT)
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# UDP 帧编解码
#
# 隧道内承载多路 UDP 会话，所有帧都长这样：
#     [1B 指令][4B session_id][... 各自的负载]
# 这里的三组编解码函数就是围绕这个统一前缀设计的。
# ---------------------------------------------------------------------------

def encode_udp_assoc(session_id: int, target_port: int, target_addr: str = "") -> bytes:
    """UDP_ASSOC：frps → frpc，告诉它"给这个会话分配一路到某内网 UDP 服务"。

    为什么要把 addr / port 也传给 frpc？
        一个 frpc 可能同时暴露多个内网 UDP 服务（比如 DNS 53 + 游戏 27015），
        由服务端在分配会话时明确指定目标，比让 frpc 自己猜要稳妥。
    """
    raw = target_addr.encode("utf-8")[:MAX_NAME_LEN]
    return (
        UDP_ASSOC
        + struct.pack("!I", session_id & 0xFFFFFFFF)
        + struct.pack("!H", target_port)
        + struct.pack("!B", len(raw))
        + raw
    )


def decode_udp_assoc(payload: bytes) -> "tuple[int, int, str]":
    """解析 UDP_ASSOC 的负载（不含前导指令字节），返回 (session_id, port, addr)。"""
    if len(payload) < SESSION_ID_SIZE + PORT_SIZE:
        raise ValueError("UDP_ASSOC 负载长度不足")
    session_id = struct.unpack("!I", payload[:SESSION_ID_SIZE])[0]
    port = struct.unpack("!H", payload[SESSION_ID_SIZE:SESSION_ID_SIZE + PORT_SIZE])[0]
    tail = payload[SESSION_ID_SIZE + PORT_SIZE:]
    addr = ""
    if tail:
        addr_len = tail[0]
        if len(tail) < 1 + addr_len:
            raise ValueError("UDP_ASSOC 内网地址长度不足")
        addr = tail[1:1 + addr_len].decode("utf-8", errors="replace")
    return session_id, port, addr


def encode_udp_data(session_id: int, chunk: bytes) -> bytes:
    """UDP_DATA：一个 UDP 数据报。

    ★ 必须带显式长度：TCP 是字节流，`reader.read(n)` 的返回不保证
      和写入时的分片一一对应。UDP 是"消息边界敏感"的，如果靠 TCP
      的分片来还原报文，两个包可能被合并成一个、或一个包被切成两半，
      接收方就再也分不出原始报文了。
    """
    if len(chunk) > MAX_UDP_PAYLOAD:
        raise ValueError(f"UDP 数据报过长（{len(chunk)} > {MAX_UDP_PAYLOAD}）")
    return (
        UDP_DATA
        + struct.pack("!I", session_id & 0xFFFFFFFF)
        + struct.pack("!I", len(chunk))
        + chunk
    )


async def read_udp_data(reader, timeout: "float | None" = None) -> "tuple[int, bytes]":
    """读取一个 UDP_DATA 帧，返回 (session_id, payload)。

    调用方应已经读到过指令字节（用来判断是 DATA 还是别的帧）。
    这里只负责读 session_id + 长度 + 负载。
    """
    async def _read(n: int) -> bytes:
        coro = reader.readexactly(n)
        return await (asyncio.wait_for(coro, timeout) if timeout else coro)

    raw_sid = await _read(SESSION_ID_SIZE)
    session_id = struct.unpack("!I", raw_sid)[0]
    raw_len = await _read(UDP_LEN_SIZE)
    length = struct.unpack("!I", raw_len)[0]
    if length > MAX_UDP_PAYLOAD:
        raise ValueError(f"UDP 数据报声称长度过大：{length}")
    payload = await _read(length) if length else b""
    return session_id, payload


def encode_udp_close(session_id: int) -> bytes:
    """UDP_CLOSE：关闭一路 UDP 会话。"""
    return UDP_CLOSE + struct.pack("!I", session_id & 0xFFFFFFFF)


def decode_udp_close(payload: bytes) -> int:
    """解析 UDP_CLOSE 的负载，返回 session_id。"""
    if len(payload) < SESSION_ID_SIZE:
        raise ValueError("UDP_CLOSE 负载长度不足")
    return struct.unpack("!I", payload[:SESSION_ID_SIZE])[0]


# ---------------------------------------------------------------------------
# P2P 打洞：UDP 探测包
#
# 原理（NAT 打洞）：
#   双方各自从一个 UDP 套接字往对方的"公网映射地址"发包。
#   第一个包通常会被对方 NAT 丢弃（因为对方 NAT 还没有这条映射），
#   但**发出去这个动作本身**就在自己 NAT 上留下了一条映射记录；
#   于是对方回过来的包就能穿过来了。双方都这么做，洞就开了。
#
# ★ 但这里有个前提：打洞只在"双方都在 NAT 后面"时才有意义。
#   如果服务端有公网 IP（本项目的典型部署），那客户端→服务端本来
#   就是直连的，打洞不会带来任何变化 —— 这时能带来的唯一收益是
#   "数据面换成 UDP"，从而规避 TCP-over-TCP 的队头阻塞。
#
# 注意：探测包是独立的 UDP 数据报（不是 TCP 流里的帧），所以不带
# "先读 1 字节指令"的约定 —— 直接 [1B cmd][16B token] 一整包发出去。
# ---------------------------------------------------------------------------

P2P_TOKEN_SIZE = 16

def encode_p2p_info(token: bytes, udp_port: int) -> bytes:
    """P2P_INFO：服务端在握手后下发的打洞参数。

    格式：P2P_INFO + [16B 共享 token][2B 服务端 UDP 打洞端口]

    客户端据此知道"用什么 token 打、往哪个 UDP 端口打"。
    若服务端没开打洞，这条不会下发，客户端自然也就不打。
    """
    return P2P_INFO + token[:P2P_TOKEN_SIZE].ljust(P2P_TOKEN_SIZE, b"\x00") \
        + struct.pack("!H", udp_port)


def decode_p2p_info(payload: bytes) -> "tuple[bytes, int]":
    """解析 P2P_INFO 负载（不含前导指令字节），返回 (token, udp_port)。"""
    if len(payload) < P2P_TOKEN_SIZE + PORT_SIZE:
        raise ValueError("P2P_INFO 负载长度不足")
    token = payload[:P2P_TOKEN_SIZE]
    port = struct.unpack("!H", payload[P2P_TOKEN_SIZE:P2P_TOKEN_SIZE + PORT_SIZE])[0]
    return token, port


def encode_p2p_probe(token: bytes) -> bytes:
    """打洞探测包：P2P_PROBE + 16 字节会话标识。

    带上会话标识是为了让对方能确认"这个包来自本次打洞尝试"，
    而不是别的程序误发到同一端口的杂包。
    """
    return P2P_PROBE + token[:P2P_TOKEN_SIZE].ljust(P2P_TOKEN_SIZE, b"\x00")


def decode_p2p_probe(datagram: bytes) -> bytes:
    """解析一整个探测包，返回其中的会话标识（16 字节）。无 cmd 字节时返回 b''。"""
    if not datagram or datagram[:1] != P2P_PROBE:
        return b""
    return datagram[1:1 + P2P_TOKEN_SIZE].ljust(P2P_TOKEN_SIZE, b"\x00")


def encode_p2p_ready(token: bytes) -> bytes:
    """打洞成功确认包。"""
    return P2P_READY + token[:P2P_TOKEN_SIZE].ljust(P2P_TOKEN_SIZE, b"\x00")


def decode_p2p_ready(datagram: bytes) -> bytes:
    """解析一个确认包，返回其中的会话标识。无 cmd 字节时返回 b''。"""
    if not datagram or datagram[:1] != P2P_READY:
        return b""
    return datagram[1:1 + P2P_TOKEN_SIZE].ljust(P2P_TOKEN_SIZE, b"\x00")


class P2PHolePuncher:
    """UDP 打洞探测器。

    用法（两侧对称）：
        p = P2PHolePuncher(shared_token)        # ★ token 必须双方一致
        await p.open(local_port=0)              # 绑一个本地 UDP 端口
        ok = await p.attempt(peer_host, peer_port, timeout=3.0)
        if ok: ...                              # 洞已开，可以用 p.transport 收发
        p.close()

    ★ 关于 token：它必须是**双方共享**的一串随机字节（由服务端在握手时
      下发给客户端），用来确认"收到的探测包确实来自本次打洞的对端"，
      避免同机器上其他程序的 UDP 包被误判。不传则每次随机生成 ——
      那只适合同一个实例自己测自己，**不能**用来和另一端打洞。

    ★ 设计要点：**必须严格限时**。打洞在对称 NAT / 强防火墙下注定失败，
      不能让它拖慢主流程。attempt() 到点就返回 False，调用方继续走中转。
      这是"绝不因为打洞失败而影响可用性"这条硬要求的落点。
    """

    def __init__(self, shared_token: "bytes | None" = None):
        self.transport = None
        self.token = (shared_token or os.urandom(P2P_TOKEN_SIZE))[:P2P_TOKEN_SIZE]
        self.token = self.token.ljust(P2P_TOKEN_SIZE, b"\x00")
        self._probe_seen = asyncio.Event()
        self._ready_seen = asyncio.Event()
        self._peer_addr = None

    async def open(self, local_port: int = 0) -> None:
        """绑一个本地 UDP 端口（打洞必须用一个固定的套接字）。"""
        loop = asyncio.get_running_loop()
        puncher = self

        class _Proto(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                puncher.transport = transport

            def datagram_received(self, data, addr):
                puncher._on_datagram(data, addr)

        self.transport, _ = await loop.create_datagram_endpoint(
            _Proto, local_addr=("0.0.0.0", local_port)
        )

    def _on_datagram(self, data: bytes, addr) -> None:
        """收到 UDP 包：识别是对方的探测还是确认。"""
        token = decode_p2p_probe(data)
        if token:
            if token == self.token:
                # 对方打过来了 —— 立刻回一个 ready，并记下对方地址
                self._peer_addr = addr
                self._probe_seen.set()
                with contextlib.suppress(Exception):
                    self.transport.sendto(encode_p2p_ready(self.token), addr)
            return
        token = decode_p2p_ready(data)
        if token and token == self.token:
            self._peer_addr = addr
            self._ready_seen.set()

    @property
    def local_addr(self):
        """本端实际绑定的地址（用于上报给对端）。"""
        if self.transport is None:
            return None
        try:
            return self.transport.get_extra_info("sockname")
        except Exception:
            return None

    async def attempt(self, peer_host: str, peer_port: int,
                      timeout: float = 3.0, interval: float = 0.25) -> bool:
        """向对端地址反复发探测，直到收到对方回应或超时。

        返回值：
            True  —— 洞已打通（收到了对方的 probe 或 ready）
            False —— 限时内没打通（对称 NAT / 对端不可达 / 防火墙）

        ★ 唯一正确的失败处理：返回 False，让调用方走中转。
        """
        if self.transport is None:
            return False
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        probe = encode_p2p_probe(self.token)
        while loop.time() < deadline:
            try:
                self.transport.sendto(probe, (peer_host, peer_port))
            except Exception:
                return False
            # 只要收到对方的 probe/ready 就算打通
            if self._probe_seen.is_set() or self._ready_seen.is_set():
                return True
            # 等一小会儿再发下一个探测（不要打得太密，避免被当攻击）
            wait = min(interval, max(0.0, deadline - loop.time()))
            if wait <= 0:
                break
            try:
                await asyncio.wait_for(self._probe_seen.wait(), timeout=wait)
                return True
            except asyncio.TimeoutError:
                continue
        return self._probe_seen.is_set() or self._ready_seen.is_set()

    def close(self) -> None:
        if self.transport is not None:
            with contextlib.suppress(Exception):
                self.transport.close()
            self.transport = None


# ---------------------------------------------------------------------------
# TLS：证书加载
# ---------------------------------------------------------------------------

def build_server_ssl_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """构造服务端 SSL 上下文。

    每次调用都重新从文件加载，因此"证书续期后"只要再调一次本函数、
    把新 ctx 交给监听口即可生效。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return ctx


def build_client_ssl_context(
    ca_file: str = "", insecure: bool = False, no_tls: bool = False
) -> "ssl.SSLContext | None":
    """构造客户端 SSL 上下文。

    三种模式（按优先级）：
      · no_tls=True          → 返回 None，表示完全不用 TLS（明文）。
                               仅当服务端也没配证书时才这么用，否则会握手失败。
      · ca_file 指定 CA 证书 → 严格校验服务端身份（生产环境应如此）
      · insecure=True        → 不校验（仅用于自签证书的临时测试）

    三者都不满足时直接报错，避免用户"以为加密了其实没有"。
    """
    if no_tls:
        logger.warning("已禁用 TLS（--no_tls），本次为明文传输")
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning("已关闭证书校验（insecure 模式），仅建议在测试环境使用")
    elif ca_file:
        ctx.load_verify_locations(cafile=ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
    else:
        raise ValueError("必须提供 --ca_file，或显式指定 --insecure / --no_tls")

    return ctx


def cert_days_left(cert_file: str) -> "float | None":
    """读取证书剩余有效天数。读不出（无 cryptography / 文件损坏）返回 None。"""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return None

    try:
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        # not_valid_after_utc 是 cryptography 42+ 的新属性，
        # 老版本只有 not_valid_after（无时区），这里做兼容
        expiry = getattr(cert, "not_valid_after_utc", None)
        if expiry is None:
            import datetime
            expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        import datetime as _dt
        delta = expiry - _dt.datetime.now(_dt.timezone.utc)
        return delta.total_seconds() / 86400.0
    except Exception as exc:  # 证书格式异常等，不该让整个程序起不来
        logger.warning("读取证书有效期失败: %s", exc)
        return None


# ---------------------------------------------------------------------------
# 统计计数
# ---------------------------------------------------------------------------

class Stats:
    """运行统计。所有计数都由单线程事件循环访问，天然无竞态，无需加锁。"""

    def __init__(self):
        self.started_at = time.time()
        self.connections_accepted = 0   # 累计接受的外部用户连接（TCP）
        self.connections_active = 0     # 当前正在转发的连接（TCP）
        self.tunnels_established = 0    # 累计建立的隧道数
        self.bytes_forwarded = 0        # 累计转发字节数
        self.auth_failures = 0          # 鉴权失败次数
        self.rejected_overload = 0      # 因超限被拒次数
        self.rejected_timeout = 0       # 排队超时被拒次数
        self.rejected_offline = 0       # 内网未在线时被拒次数
        self.cert_renewals = 0          # 证书自动续期次数
        # --- UDP ---
        self.udp_sessions_opened = 0    # 累计打开的 UDP 会话数（按来源地址）
        self.udp_sessions_active = 0    # 当前活跃的 UDP 会话数
        self.udp_datagrams = 0          # 累计转发的 UDP 数据报个数
        self.udp_bytes = 0              # 累计转发的 UDP 字节数（负载部分）
        self.udp_rejected = 0           # 因会话数超限被拒的 UDP 数据报
        # --- P2P 打洞 ---
        self.p2p_attempts = 0           # 累计打洞尝试次数
        self.p2p_success = 0            # 累计打洞成功次数

    def summary(self) -> str:
        """生成一行摘要，方便周期性打印或落盘。"""
        uptime = time.time() - self.started_at
        udp = ""
        if self.udp_datagrams or self.udp_sessions_active:
            udp = (
                f" | UDP会话 {self.udp_sessions_active} 数据报 {self.udp_datagrams} "
                f"{format_bytes(self.udp_bytes)}"
            )
        p2p = ""
        if self.p2p_attempts:
            p2p = f" | P2P 尝试{self.p2p_attempts} 成功{self.p2p_success}"
        return (
            f"运行 {uptime:.0f}s | 用户连接 累计{self.connections_accepted} 活跃{self.connections_active} "
            f"| 隧道 {self.tunnels_established} | 转发 {format_bytes(self.bytes_forwarded)} "
            f"| 拒绝(超载{self.rejected_overload} 超时{self.rejected_timeout} 离线{self.rejected_offline}) "
            f"| 鉴权失败 {self.auth_failures} | 证书续期 {self.cert_renewals}"
            + udp + p2p
        )


def format_bytes(n: int) -> str:
    """把字节数转成人类可读的形式，如 1.5 MB。"""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n} B"


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

async def close_writer(writer: asyncio.StreamWriter) -> None:
    """安全地关闭一个 StreamWriter —— 关不掉也不许抛异常。

    原来两端都只写了 writer.close()，没有 await wait_closed()，
    导致 TCP 连接可能还停留在 TIME_WAIT / 未彻底释放。
    """
    if writer is None:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:  # 对端已经走了、event loop 正在关闭 等，忽略即可
        pass


async def cancel_task(task: "asyncio.Task | None", timeout: float = 5.0) -> None:
    """取消一个任务，并等它真正结束（带超时兜底）。

    为什么不能只写 task.cancel() 就完事？
        cancel() 只是"发出取消请求"，任务可能还卡在某个 await 上，
        要等事件循环调度到它、抛出 CancelledError 并走完清理逻辑才算真的结束。
        所以必须再 await 一次；而 await 一个被取消的任务会抛 CancelledError，
        这里用 return_exceptions=True 把它吞掉，让调用方无感知。

    为什么要加 timeout？
        ★ 实测踩过的坑（Windows + asyncio.Server）：
        某些任务在被取消时会在自己的清理逻辑里**永久悬挂**
        （典型如 Server.serve_forever() 取消时会 await wait_closed()，
         而 wait_closed() 在有活跃连接时不返回）。
        如果这里死等，整个退出流程就被拖住。加超时后：
        超时就放弃等待，让事件循环继续往下走（进程最终退出会回收一切）。
    """
    if task is None or task.done():
        return
    task.cancel()
    try:
        await asyncio.wait_for(
            asyncio.gather(task, return_exceptions=True), timeout=timeout
        )
    except (asyncio.TimeoutError, asyncio.CancelledError):
        # 任务赖着不退：不再等它，交给进程退出时回收。
        pass


async def read_cmd(reader: asyncio.StreamReader) -> bytes:
    """读取 1 字节指令。连不上或对端关闭时返回 b''。"""
    try:
        return await reader.readexactly(CMD_SIZE)
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        return b""


def backoff_delay(attempt: int,
                  base: float = RECONNECT_INTERVAL,
                  cap: float = RECONNECT_MAX_INTERVAL,
                  jitter: float = RECONNECT_JITTER) -> float:
    """计算第 attempt 次重连前的等待秒数（指数退避 + 随机抖动）。

    为什么要退避 + 抖动？
        · 不退避：服务端宕机时，所有客户端每 5 秒齐步重连一次，
          服务端一恢复就被瞬间打满（惊群）。
        · 只退避不抖动：多个客户端仍会在同一秒重连（它们的失败时刻接近）。
        加了随机抖动后，重连请求会被摊平到一段时间里。

    参数 attempt 从 1 开始（第一次失败传 1），返回 base * 2^(attempt-1)，
    上限 cap，再叠加 ±jitter 比例的随机扰动。
    """
    import random
    delay = min(cap, base * (2 ** max(0, attempt - 1)))
    if jitter > 0:
        # 在 [1-jitter, 1+jitter] 区间内随机缩放
        delay *= 1.0 + random.uniform(-jitter, jitter)
        delay = max(0.5, delay)
    return delay


def touch(writer) -> None:
    """记录"刚刚收到过对端数据"，供 watchdog 判断假死。

    调用方每读到对端任何字节（心跳、指令、数据）后调用一次即可。
    """
    try:
        writer._frp_last_seen = time.monotonic()
    except Exception:
        pass


async def watchdog(writer,
                   label: str,
                   timeout: float = HEARTBEAT_TIMEOUT,
                   ping: bytes = PING,
                   interval: float = HEARTBEAT_INTERVAL) -> None:
    """连接保活 + 假死检测的通用"看门狗"。

    它做两件事（合在一个循环里，省一个协程）：
      1) 每 interval 秒往对端发一个 ping 字节，防止 NAT / 防火墙
         把"看起来空闲"的连接静默掐掉；
      2) 检查距离上次**收到**对端任何字节过了多久 —— 超过 timeout
         就判定这条连接已死，主动关闭 writer。

    ★ 为什么需要"假死检测"（而不是只靠 read 返回 b''）？
      TCP 半开（half-open）是很常见的故障：对端进程崩了、网线拔了、
      中间设备丢了状态，本端的 socket 依然显示"已连接"，read 会一直
      阻塞 —— 不报错、也不返回 EOF。只靠 read 的代码会永远挂在这里。
      唯一可靠的办法就是"超时没收到任何东西 = 判死"。

    配套用法：
      · 建连后立刻调用一次 touch(writer)，给个初始时刻；
      · 之后每读到对端任何字节，都再 touch(writer) 一次；
      · 本协程负责周期性发 ping 并在超时时关闭连接。
    """
    try:
        while True:
            await asyncio.sleep(interval)
            # 1) 保活：发一个 ping 字节
            try:
                writer.write(ping)
                await writer.drain()
            except (ConnectionError, OSError):
                return
            # 2) 假死检测
            last_seen = getattr(writer, "_frp_last_seen", None)
            if last_seen is not None and time.monotonic() - last_seen > timeout:
                logger.warning("[%s] %d 秒内未收到对端任何数据，判定连接已死",
                               label, int(timeout))
                with contextlib.suppress(Exception):
                    writer.close()
                return
    except asyncio.CancelledError:
        raise


async def stream_copy(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tag: str = "",
    stats: "Stats | None" = None,
    idle_timeout: "float | None" = None,
) -> None:
    """单向数据泵：从 reader 读，往 writer 写，直到某一端结束。

    这是整个内网穿透的「心脏」—— 每条数据通路都由两个方向相反的本函数组成。

    三个关键细节（也是原版容易踩坑的地方）：

    1) writer.write(data) 是同步的，数据只是进了内核缓冲区就先返回；
       真正需要等待的是 writer.drain()。它保证「发得快、收得慢」时
       数据不会在内存里无限堆积 —— 这就是所谓的背压（backpressure）。

    2) 每次循环都必须 await，把控制权还给事件循环，否则这一个连接会把
       整个单线程的事件循环独占，其他连接全部卡死。

    3) 退出时只关 writer（关闭写方向，让对端读到 EOF），
       不去关 reader，避免误闭对方仍在使用的连接。

    可选参数 idle_timeout（秒）：
        ★ 数据隧道**不能**像控制连接那样注入心跳字节（会污染用户数据流），
          所以只能靠"多久没读到数据"来判断连接是否已经假死。
          给了这个参数后，超过该时长没读到任何数据即认为连接已死、收工。
          设为 None（默认）表示不做空闲检测，保持原行为 ——
          这样既能让隧道用上假死检测，又不影响"本来就该长时间安静"
          的场景（比如某些长轮询）。
    """
    try:
        while True:
            if idle_timeout is None:
                data = await reader.read(CHUNK_SIZE)
            else:
                try:
                    data = await asyncio.wait_for(
                        reader.read(CHUNK_SIZE), timeout=idle_timeout
                    )
                except asyncio.TimeoutError:
                    logger.debug("[%s] 空闲 %d 秒无数据，判定连接已死",
                                 tag, int(idle_timeout))
                    break
            if not data:  # 读到空字节 == 对端已关闭（EOF）
                break
            writer.write(data)
            await writer.drain()  # 背压控制点，缺了它大流量下会 OOM
            if stats is not None:
                stats.bytes_forwarded += len(data)
    except asyncio.CancelledError:
        # 任务被主动取消（正常收尾流程），不属于错误，直接向上抛
        raise
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        logger.debug("[%s] 连接中断: %s", tag, exc)
    except Exception as exc:  # 兜底，绝不让异常逃逸成「任务异常未回收」
        logger.warning("[%s] 转发异常: %s", tag, exc)
    finally:
        await close_writer(writer)
