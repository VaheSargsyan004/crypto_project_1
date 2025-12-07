from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def load_private(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public(path_or_bytes):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    if isinstance(path_or_bytes, str) and path_or_bytes.endswith(".pem"):
        with open(path_or_bytes, "rb") as f:
            return load_pem_public_key(f.read())
    else:
        return load_pem_public_key(path_or_bytes)

def sign_data(private_key, data_bytes):
    return private_key.sign(data_bytes, padding.PKCS1v15(), hashes.SHA256())

def verify_signature(public_key, data_bytes, signature):
    try:
        public_key.verify(signature, data_bytes, padding.PKCS1v15(), hashes.SHA256())
        return True
    except:
        return False
