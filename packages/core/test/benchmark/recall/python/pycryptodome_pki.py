"""Legacy PKI shim.

An older billing partner still hands us DSA-signed manifests and expects
RSA-signed receipts in return. We keep this on PyCryptodome because the vendor
SDK we integrate with pins that library; the rest of the platform has moved on
to `cryptography`.
"""

from __future__ import annotations

from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256


def new_receipt_key(bits: int = 2048) -> RSA.RsaKey:
    return RSA.generate(bits)


def new_manifest_key(bits: int = 2048) -> DSA.DsaKey:
    return DSA.generate(bits)


def sign_receipt(receipt_key: RSA.RsaKey, receipt: bytes) -> bytes:
    digest = SHA256.new(receipt)
    return pkcs1_15.new(receipt_key).sign(digest)


def sign_manifest(manifest_key: DSA.DsaKey, manifest: bytes) -> bytes:
    digest = SHA256.new(manifest)
    signer = DSS.new(manifest_key, "fips-186-3")
    return signer.sign(digest)


def verify_manifest(pub: DSA.DsaKey, manifest: bytes, signature: bytes) -> bool:
    digest = SHA256.new(manifest)
    try:
        DSS.new(pub, "fips-186-3").verify(digest, signature)
        return True
    except ValueError:
        return False
