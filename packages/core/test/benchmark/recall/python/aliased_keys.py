"""Account key material.

Two long-lived key types per tenant:

  * an RSA key for encrypting webhook payloads that partner systems can only
    open with RSA-OAEP, and
  * an Ed25519 key for signing outbound events.

The asymmetric primitives are imported under short local aliases so the rest
of the module reads a little cleaner.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.asymmetric import ed25519 as _eddsa
from cryptography.hazmat.primitives.asymmetric import padding as _pad


def mint_encryption_key(bits: int = 3072) -> _rsa.RSAPrivateKey:
    return _rsa.generate_private_key(public_exponent=65537, key_size=bits)


def mint_signing_key() -> _eddsa.Ed25519PrivateKey:
    return _eddsa.Ed25519PrivateKey.generate()


def seal_for_partner(pub: _rsa.RSAPublicKey, plaintext: bytes) -> str:
    ct = pub.encrypt(
        plaintext,
        _pad.OAEP(
            mgf=_pad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ct).decode()


def sign_event(sk: _eddsa.Ed25519PrivateKey, body: bytes) -> str:
    return base64.b64encode(sk.sign(body)).decode()


def export_public(sk: _eddsa.Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
