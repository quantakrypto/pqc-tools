import jwt

def issue(payload, key):
    return jwt.encode(payload, key, algorithm="RS256")

def verify(token, key):
    return jwt.decode(token, key, algorithms=["ES256"])
