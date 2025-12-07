import socket, json, os
from utils.crypto_utils import load_public, verify_signature
from utils.aes_utils import aes_encrypt, aes_decrypt

HOST = "127.0.0.1"
PORT = 5000

def verify_certificate(cert):
    ca_pub = load_public("ca/ca_public_key.pem")

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

    cert = json.loads(s.recv(4096).decode())
    print("Certificate received.")

    if not verify_certificate(cert):
        print("❌ Certificate verification failed.")
        return

    print("✔️ Certificate is valid!")

    server_pub = load_public(cert["public_key"].encode())

    # Step 2 — Generate AES session key
    session_key = os.urandom(32)
    encrypted_key = server_pub.encrypt(
        session_key,
        padding.PKCS1v15()
    )
    s.send(encrypted_key)

    print("AES session key sent.")

    # Step 3 — Secure messaging
    while True:
        msg = input("You: ").encode()
        s.send(aes_encrypt(session_key, msg))

        resp = s.recv(4096)
        print("Server:", aes_decrypt(session_key, resp).decode())

start_client()
