"""Deploy runner.

Opens an SSH session to a release host, runs the deploy script, and streams
back the output. Host-key and kex algorithm preferences are pinned so a
downgraded server can't quietly negotiate something weaker than we allow.
"""

from __future__ import annotations

import paramiko


# Ordered algorithm preferences pushed onto the transport before auth.
PREFERRED_KEX = [
    "curve25519-sha256",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group14-sha256",
]
PREFERRED_HOST_KEYS = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "rsa-sha2-512",
]


def connect(host: str, user: str, key_path: str, port: int = 22) -> paramiko.SSHClient:
    # Ed25519 deploy key; falls back to nothing (no password auth allowed).
    pkey = paramiko.Ed25519Key.from_private_key_file(key_path)

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=user,
        pkey=pkey,
        allow_agent=False,
        look_for_keys=False,
        disabled_algorithms={
            "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"],
            "keys": ["ssh-rsa", "ssh-dss"],
        },
    )

    transport = client.get_transport()
    if transport is not None:
        opts = transport.get_security_options()
        opts.kex = PREFERRED_KEX
        opts.key_types = PREFERRED_HOST_KEYS
    return client


def run_deploy(client: paramiko.SSHClient, script: str) -> tuple[int, str]:
    stdin, stdout, stderr = client.exec_command(script)
    stdin.close()
    out = stdout.read().decode() + stderr.read().decode()
    code = stdout.channel.recv_exit_status()
    return code, out
