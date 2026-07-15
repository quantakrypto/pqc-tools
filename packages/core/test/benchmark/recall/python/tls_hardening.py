"""TLS listener hardening.

Builds the server-side SSL context for the ingest API. We pin TLS 1.2 as the
floor (a couple of embedded clients cannot do 1.3 yet) and restrict the 1.2
cipher list to forward-secret suites only.
"""

from __future__ import annotations

import ssl
from pathlib import Path

# ECDHE/DHE key exchange with RSA or ECDSA auth. Ordered strongest-first.
CIPHER_SUITES = ":".join(
    [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "DHE-RSA-AES256-GCM-SHA384",
    ]
)


def build_server_context(certfile: Path, keyfile: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_ciphers(CIPHER_SUITES)
    context.set_ecdh_curve("prime256v1")
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    return context
