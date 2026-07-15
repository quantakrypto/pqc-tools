"""Key-agreement toolkit for the transport layer.

We support three negotiated groups depending on peer capabilities:

  * x25519   -- default for modern peers
  * x448     -- opt-in for peers that demand a larger group
  * p256-ecdh -- fallback for legacy hardware that only speaks NIST curves

All three derive a 32-byte traffic key via HKDF over the raw shared secret.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448


def _kdf(shared_secret: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def agree_x25519(peer_public: x25519.X25519PublicKey, info: bytes = b"tls-x25519") -> bytes:
    ephemeral = x25519.X25519PrivateKey.generate()
    shared = ephemeral.exchange(peer_public)
    return _kdf(shared, info)


def agree_x448(peer_public: x448.X448PublicKey, info: bytes = b"tls-x448") -> bytes:
    ephemeral = x448.X448PrivateKey.generate()
    shared = ephemeral.exchange(peer_public)
    return _kdf(shared, info)


def agree_p256(peer_public: ec.EllipticCurvePublicKey, info: bytes = b"tls-p256") -> bytes:
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared = ephemeral.exchange(ec.ECDH(), peer_public)
    return _kdf(shared, info)


NEGOTIATION_ORDER = ("x25519", "x448", "p256-ecdh")
