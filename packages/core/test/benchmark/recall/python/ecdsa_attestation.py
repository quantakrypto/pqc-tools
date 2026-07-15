"""Device attestation helper.

Each edge device holds a P-256 key in its secure element. The fleet service
verifies boot measurements signed with that key before handing out a session
token. This module models the host-side verification and a test-only signer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature


@dataclass(frozen=True)
class Measurement:
    device_id: str
    pcr0: str
    firmware_version: str

    def canonical(self) -> bytes:
        return json.dumps(self.__dict__, sort_keys=True, separators=(",", ":")).encode()


def new_device_key() -> ec.EllipticCurvePrivateKey:
    # NIST P-256 -- matches the curve baked into the secure element.
    return ec.generate_private_key(ec.SECP256R1())


def attest(signing_key: ec.EllipticCurvePrivateKey, measurement: Measurement) -> bytes:
    return signing_key.sign(measurement.canonical(), ec.ECDSA(hashes.SHA256()))


def verify_attestation(
    public_key: ec.EllipticCurvePublicKey,
    measurement: Measurement,
    signature: bytes,
) -> bool:
    try:
        public_key.verify(signature, measurement.canonical(), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def verify_prehashed(public_key, digest: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False
