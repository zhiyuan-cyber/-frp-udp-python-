"""
cert_renew.py —— 证书自动续期

解决的问题：
    自签证书都有有效期（默认 825 天）。到期前如果没人管，服务端会在某天
    突然因为"证书过期"而无法建立 TLS 连接 —— 且往往是半夜才被发现。

两种方案对比：
    · 手动续期：到期前人工跑一次 gen_cert.py 再重启服务 —— 靠人记，容易忘
    · 自动续期：程序每次启动、以及每天定时检查，剩余有效期不足阈值就自动重签
                —— 本模块采用这个方案

关键前提：**CA 私钥必须留着**。续期是用 CA 重新签一张服务端证书；
    CA 私钥丢了就只能重新生成 CA，而所有客户端都得换 CA 文件，那就不是"自动"了。

为什么续期后不用重启？
    我们把"重新加载证书"封装成一次 `ssl.SSLContext` 重建 + 换给监听口。
    已有的连接不受影响（TLS 握手只在连接建立时发生），新连接立刻用上新证书。
"""

import os
import time

from protocol import get_logger

logger = get_logger("frp.cert")

# 剩余有效期少于这个天数就触发续期。
# 30 天是个经验值：足够覆盖"节假日没人管"的窗口，又不至于频繁重签。
RENEW_THRESHOLD_DAYS = 30

# 运行中检查的间隔（秒）。默认每天查一次 —— 证书是以"天"为单位过期的，
# 没必要查得太勤；每次检查只是 stat + 解析一个 PEM，开销可忽略。
RENEW_CHECK_INTERVAL = 24 * 3600


def _load_cert_module():
    """延迟导入 cryptography。

    为什么要延迟导入？因为 frps/frpc 的主体功能（转发）只依赖标准库，
    不想让"没装 cryptography 的用户"连启动都做不到。
    只有真正用到证书检查/续期时才 import，缺了就给个清晰提示。
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        return x509, hashes, serialization, rsa, NameOID
    except ImportError:
        logger.warning("未安装 cryptography，无法检查/自动续期证书（pip install cryptography）")
        return None


def days_until_expiry(cert_file: str) -> "float | None":
    """返回证书剩余有效天数；读不出来返回 None。"""
    mods = _load_cert_module()
    if mods is None:
        return None
    x509, _, _, _, _ = mods

    import datetime
    try:
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        expiry = getattr(cert, "not_valid_after_utc", None)
        if expiry is None:
            expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        return (expiry - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 86400.0
    except Exception as exc:
        logger.warning("解析证书 %s 失败: %s", cert_file, exc)
        return None


def renew_certificate(
    ca_cert_file: str,
    ca_key_file: str,
    cert_file: str,
    key_file: str,
    hosts: "list[str]",
    days: int = 825,
) -> bool:
    """用 CA 重新签发服务端证书，覆盖写入 cert_file / key_file。

    返回是否成功。失败时**保留原证书不动** —— 宁可用一张快过期的证书，
    也不能因为续期出错把能用的证书覆盖坏了。
    """
    mods = _load_cert_module()
    if mods is None:
        return False
    x509, hashes, serialization, rsa, NameOID = mods

    import datetime
    import ipaddress

    try:
        # 1) 读 CA 证书与私钥
        with open(ca_cert_file, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(ca_key_file, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        # 2) 生成新的服务端密钥
        srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # 3) 组装 SAN（Subject Alternative Name）—— 现代 TLS 校验的主体依据
        san_entries = []
        for h in hosts:
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(h)))
            except ValueError:
                san_entries.append(x509.DNSName(h))

        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hosts[0] if hosts else "localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "aio-frp"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        new_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_cert.subject)          # 由 CA 签发
            .public_key(srv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        # 4) 先写临时文件再原子替换 —— 避免"写到一半崩了"留下半截坏证书
        _atomic_write(cert_file, new_cert.public_bytes(serialization.Encoding.PEM))
        _atomic_write(key_file, srv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        logger.info("证书已续期：%s（有效期 %d 天）", cert_file, days)
        return True

    except Exception as exc:
        logger.error("证书续期失败，保留原证书: %s", exc)
        return False


def _atomic_write(path: str, data: bytes) -> None:
    """原子写：先写同目录的临时文件，再 os.replace 覆盖目标。

    os.replace 在同一文件系统内是原子操作，不存在"读到半截文件"的窗口。
    """
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    if os.name != "nt":  # 私钥尽量收紧权限（Windows 上忽略）
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def ensure_valid_cert(
    cert_file: str,
    key_file: str,
    ca_cert_file: str = "",
    ca_key_file: str = "",
    hosts: "list[str] | None" = None,
    threshold_days: int = RENEW_THRESHOLD_DAYS,
    days: int = 825,
) -> bool:
    """检查证书，必要时续期。返回证书是否处于健康状态（含刚续期成功）。

    三种情况：
        · 剩余天数充足            → 不动，返回 True
        · 剩余不足且 CA 齐全      → 续期，返回续期结果
        · 剩余不足但 CA 不全      → 报警告，返回 False（但仍让程序继续跑，
                                    用旧证书撑到人工处理，比直接起不来好）
    """
    left = days_until_expiry(cert_file)
    if left is None:
        return True  # 读不出来（没装 cryptography 等），不做判断也不阻塞启动

    if left > threshold_days:
        logger.info("证书剩余 %.1f 天，无需续期", left)
        return True

    logger.warning("证书仅剩 %.1f 天（阈值 %d 天），准备自动续期", left, threshold_days)

    if not (ca_cert_file and ca_key_file):
        logger.error(
            "无法自动续期：缺少 CA 证书/私钥（--ca_cert_file / --ca_key_file）。"
            "请手动重新签发，或补上 CA 文件。"
        )
        return False
    if not (os.path.exists(ca_cert_file) and os.path.exists(ca_key_file)):
        logger.error("无法自动续期：CA 文件不存在（%s / %s）", ca_cert_file, ca_key_file)
        return False

    ok = renew_certificate(
        ca_cert_file, ca_key_file, cert_file, key_file,
        hosts or ["localhost"], days=days,
    )
    return ok


async def cert_renew_loop(
    cert_file: str,
    key_file: str,
    ca_cert_file: str,
    ca_key_file: str,
    hosts: "list[str]",
    on_renewed,
    threshold_days: int = RENEW_THRESHOLD_DAYS,
    interval: int = RENEW_CHECK_INTERVAL,
    stats=None,
) -> None:
    """运行中的周期性证书检查。

    每天检查一次；一旦续期成功，调用 `on_renewed()` 通知调用方
    **重新加载证书**（重建 SSLContext 并换给监听口）。
    """
    import asyncio

    try:
        while True:
            await asyncio.sleep(interval)
            left = days_until_expiry(cert_file)
            if left is None or left > threshold_days:
                logger.debug("周期检查：证书剩余 %s 天，无需处理", left)
                continue
            logger.warning("周期检查：证书仅剩 %.1f 天，触发续期", left)
            if ensure_valid_cert(
                cert_file, key_file, ca_cert_file, ca_key_file,
                hosts, threshold_days,
            ):
                # 注意：计数由 on_renewed（即 reload_certificates）统一 +1，
                # 这里不再重复累加，避免一次续期被记成两次。
                await on_renewed()
    except asyncio.CancelledError:
        raise
