from cryptography.hazmat.primitives.asymmetric import x25519, x448, ed25519

xk = x25519.X25519PrivateKey.generate()
xk448 = x448.X448PrivateKey.generate()
edk = ed25519.Ed25519PrivateKey.generate()
