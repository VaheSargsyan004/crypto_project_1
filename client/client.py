import socket
import json
import os
import sys
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

# Add project root to path
BASE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.join(BASE_DIR, "..")
sys.path.insert(0, PROJECT_ROOT)

from utils.crypto_utils import load_public, verify_signature
from utils.aes_utils import aes_encrypt, aes_decrypt

HOST = "127.0.0.1"
PORT = 5000

def verify_certificate(cert):
    # Load CA certificate and extract public key
    ca_cert_path = os.path.join(PROJECT_ROOT, "ca", "certificates", "ca_cert.pem")
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    ca_pub = ca_cert.public_key()

    # Prepare payload for signature verification
    payload = json.dumps({
        "server": cert["server"],
        "public_key": cert["public_key"],
        "expires": cert["expires"]
    }).encode()

    signature = bytes.fromhex(cert["signature"])

    return verify_signature(ca_pub, payload, signature)

def start_client():
    s = socket.socket()
    s.connect((HOST, PORT))

    # Receive server certificate (JSON string)
    cert_json = s.recv(4096).decode()
    cert = json.loads(cert_json)
    print("[CLIENT] Certificate received.")

    # Save received certificate info to JSON
    cert_dir = os.path.join(BASE_DIR, "certificates")
    os.makedirs(cert_dir, exist_ok=True)
    cert_info = {
        "name": "received_server_cert",
        "received_at": datetime.now().isoformat(),
        "certificate": cert
    }
    with open(os.path.join(cert_dir, "received_server_cert_info.json"), "w") as f:
        json.dump(cert_info, f, indent=2)

    # Verify the certificate using CA public key
    if not verify_certificate(cert):
        print("❌ Certificate verification failed.")
        return
    print("✔️ Certificate verified!")

    # Load server public key from PEM string
    server_pub = load_public(cert["public_key"].encode())

    # Generate AES session key (256-bit)
    session_key = os.urandom(32)
    encrypted_key = server_pub.encrypt(session_key, padding.PKCS1v15())
    s.send(encrypted_key)
    print("[CLIENT] AES session key sent.")

    # Secure messaging loop
    while True:
        msg = input("You: ").encode()
        if not msg:
            continue
        s.send(aes_encrypt(session_key, msg))

        resp = s.recv(4096)
        print("Server:", aes_decrypt(session_key, resp).decode())

if __name__ == "__main__":
    start_client()
