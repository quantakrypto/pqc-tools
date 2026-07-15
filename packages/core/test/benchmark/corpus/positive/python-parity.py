# Parity fixture for the Python detector's audit gap-closers.
# One occurrence per NEW rule, deterministic, and deliberately free of any
# keygen / exchange that would trip an existing python rule.
import ssl
import requests
from cryptography.hazmat.primitives.asymmetric import dsa

# cryptography (hazmat) DSA key generation -> python-hazmat-dsa (DSA, hndl:false)
signing_key = dsa.generate_private_key(key_size=2048)

# Legacy TLS 1.0 protocol pinned -> python-tls-legacy-version
legacy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

# Certificate verification disabled -> python-tls-reject
response = requests.get("https://example.invalid", verify=False)
