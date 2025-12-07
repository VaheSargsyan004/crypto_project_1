import socket
import json
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from utils.crypto_utils import load_public, verify_signature
from utils.aes_utils import aes_encrypt, aes_decrypt

HOST = "127.0.0.1"
PORT = 5000

def verify_certificate(cert):
    # Load CA certificate and extract public key
    with open("../ca/ca_cert.pem", "rb") as f:
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
