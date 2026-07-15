"""On-chain payout wallet.

We hold a hot wallet on the same curve Bitcoin and Ethereum use so payout
transactions can be signed locally before broadcast. Keys never leave the
signer process; only compressed public points and DER signatures are exported.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_wallet() -> ec.EllipticCurvePrivateKey:
    # secp256k1 -- the Bitcoin/Ethereum curve.
    return ec.generate_private_key(ec.SECP256K1())


def compressed_pubkey(wallet: ec.EllipticCurvePrivateKey) -> bytes:
    return wallet.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )


def sign_transaction(wallet: ec.EllipticCurvePrivateKey, tx_digest: bytes) -> bytes:
    return wallet.sign(tx_digest, ec.ECDSA(hashes.SHA256()))


def load_wallet_from_pem(pem_bytes: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key.curve, ec.SECP256K1):
        raise ValueError("payout wallet must be on secp256k1")
    return key
