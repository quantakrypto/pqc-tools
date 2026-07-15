from cryptography.hazmat.primitives.asymmetric import ec


def agree(private_key, peer_public_key):
    # A file that only performs the exchange on a loaded key — no keygen — was
    # previously invisible to the scanner (the ec.ECDH() agreement is the HNDL event).
    return private_key.exchange(ec.ECDH(), peer_public_key)
