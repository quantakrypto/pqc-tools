def connect(key_type):
    """Open an SSH connection.

    :param key_type: the host-key algorithm to request, for example
        "ssh-ed25519" or "ssh-rsa". Historically "ssh-dss" and the
        "diffie-hellman-group14-sha256" kex were common, and JWTs used "RS256".
        These names appear only inside this docstring (prose), so they must not
        be flagged.
    """
    return key_type
