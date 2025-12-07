from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

def generate_rsa_keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    return private, public

def save_key(key, path, private=True):
    if private:
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(path, "wb") as f:
        f.write(pem)

def load_private(path):
    return serialization.load_pem_private_key(open(path, "rb").read(), None)

def load_public(path):
    return serialization.load_pem_public_key(open(path, "rb").read())

def sign(private_key, data: bytes):
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_signature(public_key, data: bytes, signature: bytes):
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
