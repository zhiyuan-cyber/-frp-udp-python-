"""
test_multiclient.py —— 多客户端 + token 轮换 + 证书自动续期 的端到端测试

用多进程跑：主进程管调度与断言，子进程跑内网服务和各个 frpc。

覆盖用例：
    【多客户端】
      1. 两个客户端注册不同名字/端口，各自穿透互不干扰
      2. 同一个用户端口指向正确的客户端（不会串台）
      3. 服务端能同时看到两个在线客户端

    【token 轮换】
      4. 服务端配置 [新token, 旧token]，用旧 token 的客户端仍能连上（过渡期）
      5. 用不在列表里的 token 会被拒
      6. token 文件热重载：改文件后新 token 立即生效，无需重启服务端

    【证书自动续期】
      7. 证书临期时自动续期（用一个只剩几天的证书触发）
      8. 续期后证书剩余天数变长，且新证书能被原有 CA 校验通过

运行： python test_multiclient.py
"""

import asyncio
import os
import shutil
import ssl
import subprocess
import sys

sys.path.insert(0, ".")

from protocol import get_logger

logger = get_logger("e2e-multi")

HERE = os.path.dirname(os.path.abspath(__file__))
PYEXE = sys.executable
CERT = os.path.join(HERE, "certs")

SERVE_PORT = 19300
TOKEN_NEW = "token-new-2026"
TOKEN_OLD = "token-old-2025"
TOKEN_FILE = os.path.join(HERE, "tokens.txt")

# 两个客户端：rdp 走 9001，web 走 9002
CLIENT_A = {"name": "rdp", "port": 19301, "local": 19401, "body": "SERVICE-RDP"}
CLIENT_B = {"name": "web", "port": 19302, "local": 19402, "body": "SERVICE-WEB"}

results = {}


# ---------------------------------------------------------------- 子进程代码
def local_service_code(port: int, body: str) -> str:
    return f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")

async def fake(reader, writer):
    await reader.read(4096)
    payload = b"{body}"
    writer.write(b"HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s"
                 % (len(payload), payload))
    await writer.drain()
    writer.close()

async def main():
    s = await asyncio.start_server(fake, "127.0.0.1", {port})
    print("READY", flush=True)
    await s.serve_forever()

asyncio.run(main())
"""


def frpc_code(name: str, remote_port: int, local_port: int,
              token: str = "", token_file: str = "") -> str:
    tok_line = f'a.token = r"{token}"' if token else ''
    tokf_line = f'a.token_file = r"{token_file}"' if token_file else 'a.token_file = ""'
    return f"""
import asyncio, sys
sys.path.insert(0, r"{HERE}")
from frpc import Frpc

class Args: pass
a = Args()
a.serve_host, a.serve_port = "127.0.0.1", {SERVE_PORT}
a.local_host, a.local_port = "127.0.0.1", {local_port}
a.proxy_name, a.remote_port = r"{name}", {remote_port}
a.ca_file, a.insecure = r"{CERT}/ca.crt", False
{tok_line}
{tokf_line}
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
    a.token = ""
    a.token_file = TOKEN_FILE
    a.cert_file = os.path.join(CERT, "server.crt")
    a.key_file = os.path.join(CERT, "server.key")
    a.ca_cert_file = os.path.join(CERT, "ca.crt")
    a.ca_key_file = os.path.join(CERT, "ca.key")
    a.cert_host = ["127.0.0.1", "localhost"]
    a.cert_renew_days = 30
    a.max_conn_per_ip = 20
    a.max_active_conns = 100
    a.max_queued = 50
    a.log_level = "INFO"
    for k, v in over.items():
        setattr(a, k, v)
    return a


async def spawn(code: str, name: str, wait: bool = True):
    proc = await asyncio.create_subprocess_exec(
        PYEXE, "-c", code,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    if wait:
        line = await asyncio.wait_for(proc.stdout.readline(), timeout=20)
        logger.info("[%s] 就绪: %s", name, line.decode(errors="replace").strip())
    return proc


async def probe(port: int, expect: bytes, tag: str) -> bool:
    """以外部用户身份走 TLS 请求指定端口，校验返回内容。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=os.path.join(CERT, "ca.crt"))
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, ssl=ctx), timeout=8
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), timeout=8)
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=3)
        ok = expect in data
        logger.info("[%s] 端口 %d → %s", tag, port, "✅ 正确" if ok else "❌ 内容不符")
        if not ok:
            logger.info("        实际收到: %r", data[:120])
        return ok
    except Exception as exc:
        logger.info("[%s] 端口 %d → ❌ 失败: %s", tag, port, exc)
        return False


def write_token_file(tokens: "list[str]"):
    """写 token 文件（首行为主 token）。"""
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write("# aio-frp token 列表：每行一个，首行为主 token\n")
        for t in tokens:
            f.write(t + "\n")


async def wait_for_clients(frps, expect: int, timeout: int = 25) -> bool:
    """等指定数量的客户端上线。"""
    for _ in range(timeout):
        await asyncio.sleep(1)
        if len(frps.sessions) >= expect:
            return True
    return False


async def main():
    from frps import Frps

    # ---------------------------------------------------------------
    logger.info("=" * 62)
    logger.info("准备：生成测试材料")
    # 备份真证书，测试结束还原（测试会触发续期，改写证书文件）
    backup = os.path.join(HERE, "_cert_backup")
    if os.path.exists(backup):
        shutil.rmtree(backup)
    shutil.copytree(CERT, backup)
    write_token_file([TOKEN_NEW, TOKEN_OLD])   # 过渡期：新旧并存

    procs = []
    try:
        # 两个内网服务
        procs.append(await spawn(local_service_code(CLIENT_A["local"], CLIENT_A["body"]),
                                 "内网服务-rdp"))
        procs.append(await spawn(local_service_code(CLIENT_B["local"], CLIENT_B["body"]),
                                 "内网服务-web"))

        # ============ 用例 1/2/3：多客户端 ============
        logger.info("=" * 62)
        logger.info("用例 1/2/3：多客户端路由")
        frps = Frps(make_frps_args())
        frps_task = asyncio.create_task(frps.start())
        await asyncio.sleep(2)

        pa = await spawn(frpc_code(CLIENT_A["name"], CLIENT_A["port"],
                                   CLIENT_A["local"], TOKEN_NEW), "frpc-rdp")
        pb = await spawn(frpc_code(CLIENT_B["name"], CLIENT_B["port"],
                                   CLIENT_B["local"], TOKEN_NEW), "frpc-web")
        procs += [pa, pb]

        online = await wait_for_clients(frps, 2)
        logger.info("在线客户端: %s", list(frps.sessions.keys()))
        results["多客户端-双双上线"] = online

        ra = await probe(CLIENT_A["port"], b"SERVICE-RDP", "rdp")
        rb = await probe(CLIENT_B["port"], b"SERVICE-WEB", "web")
        results["多客户端-rdp 穿透"] = ra
        results["多客户端-web 穿透"] = rb
        # 串台检查：rdp 的端口绝不该返回 web 的内容
        results["多客户端-不串台"] = ra and rb
        logger.info("服务端统计 | 在线[%s] | %s",
                    ",".join(frps.sessions.keys()), frps.stats.summary())

        # ============ 用例 4：旧 token 在过渡期仍可用 ============
        logger.info("=" * 62)
        logger.info("用例 4：token 过渡期（旧 token 仍可接入）")
        pc = await spawn(frpc_code("legacy", 19303, CLIENT_A["local"], TOKEN_OLD),
                         "frpc-旧token")
        procs.append(pc)
        got_legacy = await wait_for_clients(frps, 3)
        results["token过渡期-旧token可连"] = got_legacy
        logger.info("在线客户端: %s → %s", list(frps.sessions.keys()),
                    "✅ 旧 token 被接受" if got_legacy else "❌")

        # ============ 用例 5：不在列表里的 token 被拒 ============
        logger.info("=" * 62)
        logger.info("用例 5：无关 token 应被拒")
        before = frps.stats.auth_failures
        pd = await spawn(frpc_code("bad", 19304, CLIENT_A["local"], "totally-wrong-token"),
                         "frpc-坏token", wait=False)
        procs.append(pd)
        await asyncio.sleep(4)
        results["token无关被拒"] = frps.stats.auth_failures > before
        logger.info("鉴权失败: %d → %d → %s", before, frps.stats.auth_failures,
                    "✅ 已拒绝" if results["token无关被拒"] else "❌")

        # ============ 用例 6：token 文件热重载 ============
        logger.info("=" * 62)
        logger.info("用例 6：token 文件热重载（不重启服务端）")
        # 从列表里删掉旧 token，并新增一个 token-brand-new
        TOKEN_BRAND_NEW = "token-brand-new-2027"
        write_token_file([TOKEN_NEW, TOKEN_BRAND_NEW])
        # 等热重载生效（服务端每 5 秒检查一次）
        reloaded = False
        for _ in range(12):
            await asyncio.sleep(1)
            if TOKEN_OLD not in frps.tokens.tokens:
                reloaded = True
                break
        logger.info("服务端当前 token 列表: %s", frps.tokens.tokens)
        results["token热重载"] = reloaded

        # 用一个之前不存在的 token 连 —— 说明新 token 生效了
        pe = await spawn(frpc_code("brandnew", 19305, CLIENT_A["local"], TOKEN_BRAND_NEW),
                         "frpc-新token")
        procs.append(pe)
        got_new = await wait_for_clients(frps, 4)
        results["token热重载-新token可用"] = got_new
        logger.info("在线客户端: %s → %s", list(frps.sessions.keys()),
                    "✅ 新 token 已生效" if got_new else "❌")

        # ============ 用例 7/8：证书自动续期 ============
        logger.info("=" * 62)
        logger.info("用例 7/8：证书自动续期")
        await _test_cert_renewal(frps)

    finally:
        # 清理进程
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        # 还原证书
        if os.path.exists(backup):
            for fn in os.listdir(backup):
                shutil.copy2(os.path.join(backup, fn), os.path.join(CERT, fn))
            shutil.rmtree(backup)
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
        logger.info("测试材料已还原")

    # ============ 汇总 ============
    print()
    logger.info("=" * 62)
    logger.info("测试结果汇总")
    logger.info("=" * 62)
    all_ok = True
    for name, ok in results.items():
        logger.info("  %-26s %s", name, "✅ 通过" if ok else "❌ 失败")
        all_ok = all_ok and ok
    logger.info("=" * 62)
    logger.info("总结论: %s", "✅ 全部通过" if all_ok else "❌ 存在失败项")
    return 0 if all_ok else 1


async def _test_cert_renewal(frps):
    """用一个"只剩 3 天"的证书触发续期，验证续期逻辑与热加载。"""
    from cert_renew import days_until_expiry, ensure_valid_cert

    # 1) 先用 --days 3 签一张临期证书覆盖掉当前的
    subprocess.run(
        [PYEXE, os.path.join(HERE, "gen_cert.py"),
         "--host", "127.0.0.1", "--host", "localhost",
         "--out", CERT, "--days", "3"],
        check=True, capture_output=True,
    )
    left_before = days_until_expiry(os.path.join(CERT, "server.crt"))
    logger.info("已把证书换成临期的：剩余 %.1f 天", left_before)

    # 2) 触发续期（阈值 30 天，剩余 3 天 < 30 → 应该续）
    ok = ensure_valid_cert(
        os.path.join(CERT, "server.crt"),
        os.path.join(CERT, "server.key"),
        os.path.join(CERT, "ca.crt"),
        os.path.join(CERT, "ca.key"),
        hosts=["127.0.0.1", "localhost"],
        threshold_days=30,
    )
    left_after = days_until_expiry(os.path.join(CERT, "server.crt"))
    logger.info("续期结果=%s，续期后剩余 %.1f 天", ok, left_after)
    results["证书-自动续期触发"] = ok
    results["证书-有效期变长"] = (left_before is not None and left_after is not None
                                 and left_after > left_before + 100)

    # 3) 续期后的新证书必须仍能被原 CA 校验（否则客户端会全部连不上）
    try:
        from cryptography import x509
        with open(os.path.join(CERT, "server.crt"), "rb") as f:
            srv = x509.load_pem_x509_certificate(f.read())
        with open(os.path.join(CERT, "ca.crt"), "rb") as f:
            ca = x509.load_pem_x509_certificate(f.read())
        same_issuer = srv.issuer == ca.subject
        logger.info("新证书签发者 == CA 主体: %s", same_issuer)
        results["证书-仍由原CA签发"] = same_issuer
    except Exception as exc:
        logger.warning("校验签发者失败: %s", exc)
        results["证书-仍由原CA签发"] = False

    # 4) 热加载：让服务端换上续期后的证书
    try:
        await frps.reload_certificates()
        results["证书-热加载成功"] = True
        logger.info("证书已热加载到运行中的服务端")
    except Exception as exc:
        logger.warning("热加载失败: %s", exc)
        results["证书-热加载成功"] = False

    # 5) 热加载后，用新证书验证穿透仍正常。
    #    注意：重建监听口会让客户端短暂断连，它们要过几秒才重连回来，
    #    所以这里以"重试"的方式探测，而不是探一次就判失败。
    ok_probe = False
    for attempt in range(12):
        await asyncio.sleep(2)
        if await probe(CLIENT_A["port"], b"SERVICE-RDP", f"续期后#{attempt+1}"):
            ok_probe = True
            break
    results["证书-续期后仍可穿透"] = ok_probe


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
