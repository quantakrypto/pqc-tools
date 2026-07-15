# SSH transport preferred key-exchange algorithms (paramiko-style _preferred_kex).
# The classical kex is negotiated by NAME here — the harvest-now surface the
# crypto/* API rules miss.
PREFERRED_KEX = [
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group-exchange-sha256",
    "ecdh-sha2-nistp256",
    "curve25519-sha256",
]
