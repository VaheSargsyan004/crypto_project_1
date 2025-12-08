import socket, json
import os
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization

# Add project root to path
BASE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.join(BASE_DIR, "..")
sys.path.insert(0, PROJECT_ROOT)

from utils.crypto_utils import load_private, save_cert_info, sign_data
from utils.aes_utils import aes_encrypt, aes_decrypt
from cryptography.hazmat.primitives.asymmetric import padding

HOST = "127.0.0.1"
PORT = 5000

def start_server():
    print("Server started.")
    
    certs_dir = os.path.join(BASE_DIR, "certificates")
    cert_path = os.path.join(certs_dir, "server_cert.pem")
    key_path = os.path.join(certs_dir, "server_key.pem")
    
    # Save certificate info to JSON
    if os.path.exists(cert_path) and os.path.exists(key_path):
        save_cert_info(cert_path, key_path, BASE_DIR, "server")

    # Load X.509 certificate and convert to JSON format expected by client
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    
    # Extract public key as PEM
    pub_key = cert.public_key()
    pub_key_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    # Get server name from certificate (common name)
    server_name = None
    try:
        server_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, AttributeError):
        server_name = "my-server"
    
    # Load CA key to sign the certificate JSON
    ca_key_path = os.path.join(PROJECT_ROOT, "ca", "certificates", "ca_key.pem")
    ca_key = load_private(ca_key_path)
    
    # Create certificate JSON
    cert_data = {
        "server": server_name,
        "public_key": pub_key_pem,
        "expires": cert.not_valid_after.isoformat()
    }
    
    # Sign the certificate data
    payload = json.dumps(cert_data).encode()
    signature = sign_data(ca_key, payload)
    cert_data["signature"] = signature.hex()
    
    cert_json = json.dumps(cert_data)
    
    conn_socket = socket.socket()
    conn_socket.bind((HOST, PORT))
    conn_socket.listen(1)
    print(f"[SERVER] Listening on {HOST}:{PORT}...")
    conn, addr = conn_socket.accept()
    print("[SERVER] Client connected:", addr)

    # Step 1 — Send server certificate (JSON string)
    conn.send(cert_json.encode())

    # Step 2 — Receive AES session key
    server_private = load_private(key_path)
    encrypted_key = conn.recv(4096)
    aes_key = server_private.decrypt(encrypted_key, padding.PKCS1v15())
    print("[SERVER] AES session key received.")

    # Step 3 — Secure messaging
    while True:
        enc = conn.recv(4096)
        if not enc:
            break
        msg = aes_decrypt(aes_key, enc)
        print("[CLIENT]:", msg.decode())
        response = b"Message received!"
        conn.send(aes_encrypt(aes_key, response))

if __name__ == "__main__":
    start_server()
