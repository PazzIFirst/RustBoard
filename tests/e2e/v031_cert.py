#!/usr/bin/env python3
"""v0.3.1 e2e 证书辅助：构造「仅因过期」的服务端证书并做离线校验。

只使用 Python 标准库与已安装的 `cryptography`；不联网，也不打印任何私钥或
证书正文（只输出元数据与指纹）。

子命令：
  server-names --config PATH
      打印 hub 配置里 `server_names` 的 JSON 数组（用于确认过期证书的 SAN）。

  make-expired --config PATH --ca-cert PATH --ca-key PATH
               --out-cert PATH --out-key PATH
      用当前 CA 私钥签发一张**已过期**的服务端证书：
        CN=rustboard-hub，有效期 2020-01-01T00:00:00Z～2020-02-01T00:00:00Z，
        SAN 覆盖配置里的全部 server_names（并额外包含 127.0.0.1 / localhost），
        私钥与证书配套。新私钥 0600、证书 0644。

  inspect --cert PATH [--key PATH] [--ca PATH]
      输出证书元数据：指纹、有效期、CN/issuer、SAN、是否过期、是否由 CA
      签发、是否与私钥配套、文件权限。供 bash 侧做真实文件断言。
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError as exc:  # pragma: no cover - 只在缺依赖时触发
    print(
        f"v031_cert: 需要 cryptography（{exc}）；请安装后重试，脚本不会联网安装依赖",
        file=sys.stderr,
    )
    raise SystemExit(1)

UTC = datetime.timezone.utc
EXPIRED_NOT_BEFORE = datetime.datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)
EXPIRED_NOT_AFTER = datetime.datetime(2020, 2, 1, 0, 0, 0, tzinfo=UTC)
HUB_CN = "rustboard-hub"


def fail(message: str) -> "NoReturn":
    print(f"v031_cert: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_server_names(config_path: str) -> list[str]:
    """从 hub TOML 配置读取 server_names。

    优先用 tomllib（3.11+）；旧 Python 用针对该字段的正则兜底，避免额外依赖。
    """
    text = Path(config_path).read_text(encoding="utf-8")
    names = None
    try:
        import tomllib

        with open(config_path, "rb") as handle:
            parsed = tomllib.load(handle)
        value = parsed.get("server_names")
        if isinstance(value, list):
            names = [str(item) for item in value]
    except Exception:
        names = None

    if names is None:
        match = re.search(r"(?ms)^\s*server_names\s*=\s*\[(.*?)\]", text)
        if not match:
            fail(f"配置 {config_path} 中找不到 server_names 数组")
        body = match.group(1)
        names = []
        for raw in re.findall(r'"((?:[^"\\]|\\.)*)"', body):
            try:
                names.append(json.loads(f'"{raw}"'))
            except Exception:
                names.append(raw)
    if not names:
        fail(f"配置 {config_path} 的 server_names 为空，无法构造 SAN")
    return names


def load_cert(path: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(Path(path).read_bytes())
    except Exception as exc:
        fail(f"读取/解析证书失败 {path}: {exc}")


def load_private_key(path: str):
    try:
        return serialization.load_pem_private_key(
            Path(path).read_bytes(), password=None
        )
    except Exception as exc:
        fail(f"读取/解析私钥失败 {path}: {exc}")


def public_key_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def signature_valid(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    """仅验证签名，不检查有效期（过期证书也要能确认由当前 CA 签发）。"""
    public_key = ca.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def common_name(name: x509.Name) -> str:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else ""


def utc_iso(timestamp: int) -> str:
    return datetime.datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def cert_not_before(cert: x509.Certificate) -> datetime.datetime:
    """兼容 cryptography < 42：优先返回带 UTC 时区的有效期端点。"""
    value = getattr(cert, "not_valid_before_utc", None)
    if value is not None:
        return value
    return cert.not_valid_before.replace(tzinfo=UTC)


def cert_not_after(cert: x509.Certificate) -> datetime.datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=UTC)


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert_der(cert)).hexdigest()


def cert_sans(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    values: list[str] = []
    for name in extension.value:
        if isinstance(name, x509.DNSName):
            values.append(f"dns:{name.value}")
        elif isinstance(name, x509.IPAddress):
            values.append(f"ip:{name.value}")
    return values


def file_mode(path: str) -> str:
    return format(os.stat(path).st_mode & 0o777, "03o")


def write_atomic(path: str, data: bytes, mode: int) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(f"{target.name}.tmp-{os.getpid()}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(temp, mode)
    os.replace(temp, target)


def inspect_cert(cert_path: str, key_path: str | None, ca_path: str | None) -> dict:
    cert = load_cert(cert_path)
    not_before = int(cert_not_before(cert).timestamp())
    not_after = int(cert_not_after(cert).timestamp())
    now = int(datetime.datetime.now(UTC).timestamp())
    sans = cert_sans(cert)

    result = {
        "path": cert_path,
        "fingerprint": fingerprint(cert),
        "not_before": not_before,
        "not_after": not_after,
        "not_before_iso": utc_iso(not_before),
        "not_after_iso": utc_iso(not_after),
        "days_left": math.ceil((not_after - now) / 86400),
        "expired": not_after <= now,
        "subject_cn": common_name(cert.subject),
        "issuer_cn": common_name(cert.issuer),
        "sans": sans,
        "has_ip_127_0_0_1": "ip:127.0.0.1" in sans,
        "has_localhost": "dns:localhost" in sans,
        "mode": file_mode(cert_path),
        "signature_valid": None,
        "key_matches": None,
        "ca_cn": None,
    }

    if key_path:
        key = load_private_key(key_path)
        result["key_matches"] = public_key_der(key.public_key()) == public_key_der(
            cert.public_key()
        )
        result["key_mode"] = file_mode(key_path)

    if ca_path:
        ca = load_cert(ca_path)
        result["signature_valid"] = signature_valid(cert, ca)
        result["ca_cn"] = common_name(ca.subject)

    return result


def cmd_server_names(args: argparse.Namespace) -> None:
    print(json.dumps(read_server_names(args.config), ensure_ascii=False))


def cmd_make_expired(args: argparse.Namespace) -> None:
    names = read_server_names(args.config)
    # 去重并保留配置顺序；额外保证 127.0.0.1 / localhost 覆盖，便于 e2e 断言。
    ordered: list[str] = []
    for name in [*names, "127.0.0.1", "localhost"]:
        if name not in ordered:
            ordered.append(name)

    ca_cert = load_cert(args.ca_cert)
    ca_key = load_private_key(args.ca_key)
    if public_key_der(ca_key.public_key()) != public_key_der(ca_cert.public_key()):
        fail(f"CA 私钥与 CA 证书不配套：{args.ca_key} / {args.ca_cert}")

    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HUB_CN)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    )

    sans: list[x509.GeneralName] = []
    for name in ordered:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    builder = builder.add_extension(
        x509.SubjectAlternativeName(sans), critical=False
    )

    try:
        ski = ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
    except x509.ExtensionNotFound:
        pass

    # 兼容 cryptography < 42：优先 UTC 显式 API，缺失时退回已废弃接口（naive UTC）。
    if hasattr(builder, "not_valid_before_utc"):
        builder = builder.not_valid_before_utc(EXPIRED_NOT_BEFORE)
        builder = builder.not_valid_after_utc(EXPIRED_NOT_AFTER)
    else:
        builder = builder.not_valid_before(EXPIRED_NOT_BEFORE.replace(tzinfo=None))
        builder = builder.not_valid_after(EXPIRED_NOT_AFTER.replace(tzinfo=None))

    cert = builder.sign(ca_key, hashes.SHA256())

    # 写盘前自检：日期窗口、CN、SAN 覆盖、CA 签名、key 配套。
    if int(cert_not_after(cert).timestamp()) != int(
        EXPIRED_NOT_AFTER.timestamp()
    ):
        fail("生成的证书 notAfter 不符合 2020-02-01 窗口")
    if common_name(cert.subject) != HUB_CN:
        fail("生成的证书 CN 不是 rustboard-hub")
    if not signature_valid(cert, ca_cert):
        fail("生成的证书无法通过当前 CA 验签")
    if public_key_der(key.public_key()) != public_key_der(cert.public_key()):
        fail("生成的证书与私钥不配套")
    actual_sans = cert_sans(cert)
    if "ip:127.0.0.1" not in actual_sans:
        fail("生成的证书 SAN 未覆盖 127.0.0.1")

    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    write_atomic(args.out_key, key_pem, 0o600)
    write_atomic(args.out_cert, cert_pem, 0o644)

    print(
        json.dumps(
            {
                "fingerprint": fingerprint(cert),
                "not_before_iso": utc_iso(int(cert_not_before(cert).timestamp())),
                "not_after_iso": utc_iso(int(cert_not_after(cert).timestamp())),
                "subject_cn": common_name(cert.subject),
                "issuer_cn": common_name(cert.issuer),
                "sans": actual_sans,
                "cert_mode": file_mode(args.out_cert),
                "key_mode": file_mode(args.out_key),
            },
            ensure_ascii=False,
        )
    )


def cmd_inspect(args: argparse.Namespace) -> None:
    print(
        json.dumps(
            inspect_cert(args.cert, args.key, args.ca),
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="v0.3.1 e2e 证书辅助（生成过期证书 / 离线校验）"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    names = sub.add_parser("server-names", help="打印配置里的 server_names")
    names.add_argument("--config", required=True)
    names.set_defaults(func=cmd_server_names)

    expired = sub.add_parser("make-expired", help="用当前 CA 签发已过期服务端证书")
    expired.add_argument("--config", required=True)
    expired.add_argument("--ca-cert", required=True)
    expired.add_argument("--ca-key", required=True)
    expired.add_argument("--out-cert", required=True)
    expired.add_argument("--out-key", required=True)
    expired.set_defaults(func=cmd_make_expired)

    inspect = sub.add_parser("inspect", help="输出证书元数据")
    inspect.add_argument("--cert", required=True)
    inspect.add_argument("--key")
    inspect.add_argument("--ca")
    inspect.set_defaults(func=cmd_inspect)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"v031_cert: {args.command} 失败: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
