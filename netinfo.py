"""
netinfo.py —— 服务器信息探测（解析 / 归属地 / 延迟）

界面上的「服务器情况」由这里提供：
    · 解析出的 IP        —— DNS 查询
    · IP 归属地          —— 在线接口查询（带本地缓存）
    · 连接延迟（RTT）     —— TCP 连一次控制端口计时
    · 上行/下行速率       —— 由 protocol.Stats 提供，不在这里

为什么归属地要查在线接口？
    IP 地理位置库动辄几十 MB，为了显示一行字把 exe 撑大不值当。
    改成按需查询 + 本地缓存：同一个 IP 只查一次，之后离线也能显示。

★ 隐私说明：查询会把**服务器 IP** 发给第三方接口。
  内网/保留地址不会外发（本地就能判断），公网地址才查；
  界面上也会标明数据来源，用户可以选择不查。
"""

import ctypes
import ctypes.wintypes as wt
import ipaddress
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

# 查询接口（按顺序尝试，哪个通用哪个）
#   1) 太平洋电脑网：返回**中文**省市区 + 运营商，对中文用户最友好（GBK 编码）
#   2) ip.sb：英文但字段最全（含 ASN、ISP）
#   3) ipinfo.io：英文，实测较稳
_GEO_PROVIDERS = [
    {
        "name": "太平洋电脑网",
        "url": "https://whois.pconline.com.cn/ipJson.jsp?ip={ip}&json=true",
        "encoding": "gbk",
    },
    {
        "name": "ip.sb",
        "url": "https://api.ip.sb/geoip/{ip}",
        "encoding": "utf-8",
    },
    {
        "name": "ipinfo.io",
        "url": "https://ipinfo.io/{ip}/json",
        "encoding": "utf-8",
    },
]

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) frp-tunnel-assistant"
_GEO_TIMEOUT = 6.0


# ---------------------------------------------------------------------------
# 基础判断
# ---------------------------------------------------------------------------

def parse_ip(text: str) -> "ipaddress._BaseAddress | None":
    """把字符串解析成 IP 对象；不是 IP 就返回 None。"""
    try:
        return ipaddress.ip_address((text or "").strip())
    except ValueError:
        return None


def is_private(ip_text: str) -> bool:
    """是不是内网 / 回环 / 保留地址（这类地址查归属地没有意义）。"""
    ip = parse_ip(ip_text)
    if ip is None:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast)


def ip_kind(ip_text: str) -> str:
    """给界面上一个小标签：内网 / 公网 / 未知。"""
    ip = parse_ip(ip_text)
    if ip is None:
        return "未知"
    if ip.is_loopback:
        return "本机回环"
    if is_private(ip_text):
        return "内网地址"
    return "公网地址"


def resolve(host: str) -> tuple:
    """解析主机名 → (ip 或 None, 错误说明)。

    host 本身就是 IP 时直接返回它，不做 DNS（省一次查询，
    也避免某些环境里对 IP 做反查导致的超时）。
    """
    host = (host or "").strip()
    if not host:
        return None, "未填写地址"
    if parse_ip(host):
        return host, ""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return None, "DNS 解析失败：%s" % exc
    except OSError as exc:
        return None, "DNS 解析出错：%s" % exc
    # 优先返回 IPv4：很多用户看到 IPv6 会困惑，且部分网络只有 IPv4 通路
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    if v4:
        return v4[0], ""
    if infos:
        return infos[0][4][0], ""
    return None, "解析结果为空"


# ---------------------------------------------------------------------------
# 归属地查询（带缓存）
# ---------------------------------------------------------------------------

class GeoCache:
    """归属地缓存：{ip: {数据}}，落盘成 JSON。

    为什么要缓存？
        接口都有频率限制，而且界面每次刷新都去查会白白浪费；
        更重要的是——查过一次之后，断网也能照常显示。
    """

    def __init__(self, path: str, ttl_days: int = 30):
        self.path = path
        self.ttl = ttl_days * 86400
        self.data = {}
        self._load()

    def _load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                self.data = raw
        except (OSError, ValueError):
            self.data = {}

    def save(self) -> None:
        if not self.path:
            return
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except OSError:
            pass                      # 存不下就算了，不该影响主流程

    def get(self, ip: str):
        item = self.data.get(ip)
        if not item:
            return None
        if time.time() - item.get("_ts", 0) > self.ttl:
            return None
        return item

    def put(self, ip: str, info: dict) -> None:
        info = dict(info)
        info["_ts"] = time.time()
        self.data[ip] = info
        self.save()


def _http_json(url: str, encoding: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=_GEO_TIMEOUT) as resp:
        raw = resp.read()
    text = raw.decode(encoding, errors="replace").strip()
    # 有的接口会在 JSON 外面裹一层回调或空白，做一次最小化提取
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("返回内容不是 JSON：%r" % text[:80])
    return json.loads(text[start:end + 1])


def _normalize(provider_name: str, data: dict) -> dict:
    """把各家接口的字段归一成统一结构。"""
    def pick(*keys):
        for k in keys:
            v = data.get(k)
            if isinstance(v, str) and v.strip() and v.strip() not in ("0", "-"):
                return v.strip()
        return ""

    country = pick("country", "country_name")
    if not country and "china" in provider_name:
        country = "中国"
    region = pick("pro", "region", "regionName")
    city = pick("city")
    # 太平洋电脑网把"省市 + 运营商"合成了一个 addr 字段，优先用它
    addr = pick("addr")
    isp = pick("isp", "org", "organization", "asn_organization")

    # 组装一行人类可读的归属地
    if addr:
        location = addr
    else:
        parts = [p for p in (country, region, city) if p]
        # 中国 + 省份时不要重复显示"中国"
        if country in ("China", "中国") and len(parts) > 1:
            parts = parts[1:]
        location = " ".join(dict.fromkeys(parts)) or "-"
    if isp and isp not in location:
        location = "%s %s" % (location, isp)

    return {
        "location": location.strip(),
        "country": country,
        "region": region,
        "city": city,
        "isp": isp,
        "source": provider_name,
    }


def lookup_geo(ip: str, cache: "GeoCache | None" = None,
               force: bool = False) -> tuple:
    """查 IP 归属地 → (信息 dict 或 None, 错误说明)。

    依次尝试多个接口；任一个成功就返回。内网地址直接返回本地结论，不外发。
    """
    ip = (ip or "").strip()
    if not ip:
        return None, "没有 IP"

    if is_private(ip):
        return {"location": ip_kind(ip), "country": "", "region": "",
                "city": "", "isp": "", "source": "本地判断"}, ""

    if cache is not None and not force:
        hit = cache.get(ip)
        if hit:
            fresh = dict(hit)
            fresh.pop("_ts", None)
            fresh["cached"] = True
            return fresh, ""

    errors = []
    for prov in _GEO_PROVIDERS:
        url = prov["url"].format(ip=ip)
        try:
            data = _http_json(url, prov["encoding"])
            info = _normalize(prov["name"], data)
            if info["location"] and info["location"] != "-":
                if cache is not None:
                    cache.put(ip, info)
                return info, ""
            errors.append("%s：返回内容为空" % prov["name"])
        except urllib.error.HTTPError as exc:
            errors.append("%s：HTTP %s" % (prov["name"], exc.code))
        except urllib.error.URLError as exc:
            errors.append("%s：网络不可达（%s）" % (prov["name"], exc.reason))
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            errors.append("%s：%s" % (prov["name"], exc))

    return None, " / ".join(errors) if errors else "查询失败"


# ---------------------------------------------------------------------------
# 延迟探测
# ---------------------------------------------------------------------------

def tcp_latency(host: str, port: int, timeout: float = 3.0,
                attempts: int = 3) -> tuple:
    """TCP 连接计时，返回 (毫秒 或 None, 错误说明)。

    为什么要连 3 次取最小值？
        第一次连接常被 DNS/ARP/路由缓存拖慢，单次结果偏高；
        取最小值更接近真实的链路 RTT（和 ping 的直觉一致）。
    """
    best = None
    last_err = ""
    for i in range(max(1, attempts)):
        sock = None
        try:
            t0 = time.perf_counter()
            sock = socket.create_connection((host, int(port)), timeout=timeout)
            dt = (time.perf_counter() - t0) * 1000.0
            best = dt if best is None else min(best, dt)
        except socket.timeout:
            last_err = "连接超时"
        except OSError as exc:
            last_err = str(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if best is not None and best < 5:
            break                     # 已经很快，不必再测
        if i + 1 < attempts:
            time.sleep(0.15)
    return (best, "") if best is not None else (None, last_err or "探测失败")


def latency_grade(ms: float) -> tuple:
    """给延迟一个颜色分档，返回 (等级文字, 颜色)。"""
    if ms is None:
        return "—", "#9aa4b2"
    if ms < 60:
        return "极快", "#16a34a"
    if ms < 150:
        return "良好", "#22a06b"
    if ms < 300:
        return "一般", "#d97706"
    return "偏高", "#dc2626"


# ---------------------------------------------------------------------------
# 本机端口 → 占用它的进程（回答"哪个程序在用这条隧道"）
# ---------------------------------------------------------------------------
# 思路：Windows 的 iphlpapi.GetExtendedTcpTable 能一次性列出所有 TCP 端口
# 及其所属 PID（等价于 netstat -ano，但不用起子进程、快得多）。
# 拿到 PID 再用 QueryFullProcessImageName 换出可执行文件名。

_AF_INET = 2
_TCP_TABLE_OWNER_PID_LISTENER = 3
_MIB_TCP_STATE_LISTEN = 2


class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wt.DWORD),
                ("dwLocalAddr", wt.DWORD),
                ("dwLocalPort", wt.DWORD),
                ("dwRemoteAddr", wt.DWORD),
                ("dwRemotePort", wt.DWORD),
                ("dwOwningPid", wt.DWORD)]


def _pid_name(pid: int) -> str:
    """PID → 可执行文件名（取不到就返回空串）。

    PID 0/4 是内核态进程，普通权限打不开，直接给个可读名字。
    """
    if pid == 0:
        return "System Idle"
    if pid == 4:
        return "System"
    if not pid:
        return ""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k = ctypes.windll.kernel32
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wt.DWORD(1024)
        # QueryFullProcessImageNameW 在 Vista+ 可用，比 GetModuleFileNameEx 权限要求低
        if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
        return ""
    finally:
        k.CloseHandle(h)


def tcp_listeners() -> dict:
    """列出本机所有 TCP 监听端口 → {端口: (pid, 进程名)}。

    失败（非 Windows / 权限不足）时返回空字典，调用方按"查不到"处理即可。
    """
    result = {}
    try:
        iphlpapi = ctypes.windll.iphlpapi
    except (AttributeError, OSError):
        return result

    size = wt.DWORD(0)
    # 先问需要多大缓冲（必然返回 ERROR_INSUFFICIENT_BUFFER=122）
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False,
                                 _AF_INET, _TCP_TABLE_OWNER_PID_LISTENER, 0)
    if size.value <= 0:
        return result

    buf = ctypes.create_string_buffer(size.value)
    ret = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False,
                                       _AF_INET, _TCP_TABLE_OWNER_PID_LISTENER, 0)
    if ret != 0:
        return result

    count = ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0]
    # 表头是一个 DWORD，之后紧跟 count 条记录
    rows = ctypes.cast(
        ctypes.byref(buf, ctypes.sizeof(wt.DWORD)),
        ctypes.POINTER(_MIB_TCPROW_OWNER_PID))

    names = {}
    for i in range(count):
        row = rows[i]
        if row.dwState != _MIB_TCP_STATE_LISTEN:
            continue
        # 端口在网络字节序的低 16 位里
        port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        pid = int(row.dwOwningPid)
        if pid not in names:
            names[pid] = _pid_name(pid)
        result[port] = (pid, names[pid])
    return result


def port_owner(port: int) -> tuple:
    """查某个本机端口被哪个进程监听 → (pid, 进程名)，查不到返回 (0, "")。"""
    try:
        return tcp_listeners().get(int(port), (0, ""))
    except (TypeError, ValueError):
        return (0, "")


def describe_port_owner(port: int) -> str:
    """给界面用的一句话描述。"""
    pid, name = port_owner(port)
    if not pid:
        return "未发现监听进程"
    if not name:
        return "PID %d" % pid
    return "%s (PID %d)" % (name, pid)


def describe_endpoint_owner(host: str, port: int) -> str:
    """给「内网目标」一句话描述 —— 带上目标是不是本机、哪个程序在监听。

    为什么要判断 host 是不是本机？
        本机端口表只反映**这台机器**。如果客户端配置的目标是另一台机器
        （如 192.168.1.9:3306），拿本机端口表去查会得到"未发现监听进程"，
        那是误导。所以先判断，非本机就明确说明"在别的机器上"。
    """
    host = (host or "").strip().lower()
    if host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0", ""):
        ip = parse_ip(host)
        if ip is not None and not (ip.is_loopback or str(ip) == "0.0.0.0"):
            return "在 %s 上（非本机，看不到进程）" % host
    return describe_port_owner(port)


# ---------------------------------------------------------------------------
# 后台探测（避免阻塞界面）
# ---------------------------------------------------------------------------

class ServerProbe:
    """在后台线程里做一次完整探测，结果放到 self.result 供界面轮询。

    为什么用线程 + 轮询，而不是直接在界面线程里调？
        DNS 和 HTTP 都可能卡好几秒；放在界面线程里会让整个窗口"假死"。
    """

    def __init__(self, cache_path: str = ""):
        self.cache = GeoCache(cache_path) if cache_path else None
        self.result = {}
        self.busy = False
        self._thread = None
        self._lock = threading.Lock()

    def start(self, host: str, port: int, want_geo: bool = True) -> bool:
        """发起一次探测；已有探测在进行时返回 False。"""
        with self._lock:
            if self.busy:
                return False
            self.busy = True
            self.result = {"host": host, "port": port, "state": "running"}
        self._thread = threading.Thread(
            target=self._work, args=(host, port, want_geo),
            name="server-probe", daemon=True)
        self._thread.start()
        return True

    def _work(self, host: str, port: int, want_geo: bool) -> None:
        res = {"host": host, "port": port}
        t0 = time.time()
        ip, err = resolve(host)
        res["ip"] = ip
        res["resolve_error"] = err
        res["kind"] = ip_kind(ip) if ip else "未知"

        if want_geo and ip:
            info, gerr = lookup_geo(ip, self.cache)
            res["geo"] = info
            res["geo_error"] = gerr
        else:
            res["geo"] = None
            res["geo_error"] = "已跳过归属地查询" if ip else ""

        ms, lerr = tcp_latency(ip or host, port)
        res["latency_ms"] = ms
        res["latency_error"] = lerr
        res["elapsed"] = time.time() - t0
        res["state"] = "done"

        with self._lock:
            self.result = res
            self.busy = False

    def poll(self) -> dict:
        """取当前结果（含运行中状态）。"""
        with self._lock:
            return dict(self.result)
