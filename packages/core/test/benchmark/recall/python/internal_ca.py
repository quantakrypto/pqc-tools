"""Minimal internal certificate authority used to bootstrap mTLS between
services in staging. Not for production use -- keys are held in memory and
the root is self-signed with a long validity window.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def _root_subject(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Acme Internal"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Platform"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def create_root(common_name: str = "Acme Staging Root CA", valid_years: int = 10):
    # 4096-bit modulus so the root outlives the leaf certs it will sign.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = _root_subject(common_name)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * valid_years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate


def write_pem(private_key, certificate, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "root.key.pem").write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (out_dir / "root.cert.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )


def sign_blob(private_key, payload: bytes) -> bytes:
    return private_key.sign(
        payload,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


if __name__ == "__main__":
    key, cert = create_root()
    write_pem(key, cert, Path("./pki"))
    print("root fingerprint:", cert.fingerprint(hashes.SHA256()).hex())
