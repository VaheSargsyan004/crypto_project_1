import os
import json
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

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

def save_cert_info(cert_path, key_path, cert_dir, name):
    """Save certificate and key information to JSON file"""
    cert_dir_path = os.path.join(cert_dir, "certificates")
    os.makedirs(cert_dir_path, exist_ok=True)
    
    info = {"name": name, "created_at": datetime.now().isoformat()}
    
    # Read certificate info
    if os.path.exists(cert_path):
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            # Convert subject and issuer to dict
            subject_dict = {str(attr.oid): attr.value for attr in cert.subject}
            issuer_dict = {str(attr.oid): attr.value for attr in cert.issuer}
            info["certificate"] = {
                "subject": subject_dict,
                "issuer": issuer_dict,
                "serial_number": str(cert.serial_number),
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "fingerprint": cert.fingerprint(hashes.SHA256()).hex()
            }
            # Extract public key info
            pub_key = cert.public_key()
            pub_key_pem = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            info["certificate"]["public_key_pem"] = pub_key_pem
    
    # Read key info
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), None)
            pub_key = key.public_key()
            pub_key_pem = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            info["key"] = {
                "key_size": key.key_size if hasattr(key, 'key_size') else None,
                "public_key_pem": pub_key_pem
            }
    
    json_path = os.path.join(cert_dir_path, f"{name}_info.json")
    with open(json_path, "w") as f:
        json.dump(info, f, indent=2)
    
    return json_path
