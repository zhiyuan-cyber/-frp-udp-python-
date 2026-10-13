"""
gen_cert.py —— 一键生成自签 CA 与服务端证书（仅依赖标准库以外的 cryptography）

为什么需要自签证书？
    内网穿透的服务端往往是自己的云主机，没有正式域名证书。
    这时可以自己当一次 CA：签一张"服务端证书"，客户端拿这张 CA 去校验它。

生成的四个文件：
    ca.crt      CA 根证书   —— 给客户端校验用（--ca_file ca.crt）
    ca.key      CA 私钥     —— **续期必备**（--ca_key_file），务必保密
    server.crt  服务端证书  —— 给服务端加载（--cert_file）
    server.key  服务端私钥  —— 给服务端加载（--key_file），务必保密！

为什么必须保存 ca.key？
    服务端证书到期时，自动续期要用 CA 私钥重新签发。
    如果 ca.key 丢了，就只能重新生成一整套 CA，所有客户端都得换 ca.crt，
    自动续期也就失去意义了。

用法：
    python gen_cert.py                        # 生成到 certs/，含常用 SAN
    python gen_cert.py --host 110.110.110.1   # 把你的服务器 IP/域名写进证书

依赖：
    pip install cryptography
"""

import argparse
import datetime
import ipaddress
import os
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("缺少依赖：pip install cryptography", file=sys.stderr)
    raise SystemExit(1)


def make_key(bits: int = 2048):
    """生成 RSA 私钥。2048 位是当前的最低推荐强度。"""
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def build_ca():
    """生成自签的 CA 根证书（10 年有效期）。"""
    key = make_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "aio-frp Self-Signed CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "aio-frp"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                       # 自签：签发者 = 主体
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))   # 留点时钟偏差余量
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        # ★ SubjectKeyIdentifier：CA 证书的"自己的指纹"。
        #   严格实现（如 Python 3.14 自带的 OpenSSL 3.x）在链校验时，
        #   会拿子证书的 AuthorityKeyIdentifier 去 CA 证书里找这个值来配对；
        #   缺了它就会报 "Missing Authority Key Identifier" 而直接失败。
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_san(hosts: list):
    """把主机名/IP 列表转成 SAN 扩展。

    SAN（Subject Alternative Name）是现代 TLS 校验的主体依据 ——
    没有它，即使 CN 写对了，客户端也会报证书不匹配。
    """
    entries = []
    for h in hosts:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            entries.append(x509.DNSName(h))
    return x509.SubjectAlternativeName(entries)


def build_server_cert(ca_key, ca_cert, hosts: list, days: int = 825):
    """由 CA 签发服务端证书。

    有效期默认 825 天 —— 这是主流浏览器的上限约定，超过会被判定为不受信。
    """
    key = make_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hosts[0] if hosts else "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "aio-frp"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_build_san(hosts), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        # ★ 这两个扩展是 RFC 5280 对"CA 签发的证书"的要求，实打实的兼容性问题：
        #   · AuthorityKeyIdentifier（AKI）：指出签发者（CA）是谁 ——
        #     用 CA 的公钥算指纹即可，客户端靠它把本证书和 CA 配对。
        #   · SubjectKeyIdentifier（SKI）：本证书自己的指纹，便于后续吊销/链式引用。
        #   实测：缺 AKI 时，Python 3.14 附带的 OpenSSL 会在握手阶段直接报
        #   "certificate verify failed: Missing Authority Key Identifier"，
        #   而较老的 OpenSSL（如 Python 3.13 附带版本）容忍缺失 ——
        #   于是同一份证书"在老环境能跑、在新环境全挂"，非常难查。
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def write_pem(path: str, cert, key=None, key_only: bool = False):
    """把证书/私钥写成 PEM 文件。私钥文件在 Windows 上不加权限位。"""
    if key_only:
        data = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        data = cert.public_bytes(serialization.Encoding.PEM)
    with open(path, "wb") as f:
        f.write(data)
    # 私钥尽量收紧权限（Linux/macOS 有效，Windows 上会忽略）
    if key_only and os.name != "nt":
        os.chmod(path, 0o600)


def main():
    ap = argparse.ArgumentParser(description="生成自签 CA 与服务端证书")
    ap.add_argument("--out", default="certs", help="输出目录")
    ap.add_argument("--host", action="append", default=[],
                    help="服务端 IP 或域名，可重复多次。默认 localhost/127.0.0.1")
    ap.add_argument("--days", type=int, default=825, help="服务端证书有效期（天）")
    args = ap.parse_args()

    hosts = args.host or ["localhost", "127.0.0.1"]
    os.makedirs(args.out, exist_ok=True)

    ca_key, ca_cert = build_ca()
    srv_key, srv_cert = build_server_cert(ca_key, ca_cert, hosts, args.days)

    write_pem(os.path.join(args.out, "ca.crt"), ca_cert)
    write_pem(os.path.join(args.out, "ca.key"), None, key=ca_key, key_only=True)
    write_pem(os.path.join(args.out, "server.crt"), srv_cert)
    write_pem(os.path.join(args.out, "server.key"), None, key=srv_key, key_only=True)

    print(f"证书已生成到 {os.path.abspath(args.out)}/")
    print(f"  覆盖主机: {', '.join(hosts)}")
    print("  ca.crt     → 客户端用 --ca_file")
    print("  ca.key     → 服务端自动续期用 --ca_key_file（务必保密）")
    print("  server.crt → 服务端用 --cert_file")
    print("  server.key → 服务端用 --key_file（务必保密，不要外传）")


if __name__ == "__main__":
    main()
