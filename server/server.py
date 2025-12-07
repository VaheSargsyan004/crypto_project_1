import socket, json

from cryptography.hazmat.primitives import padding

from utils.crypto_utils import load_private, load_public
from utils.aes_utils import aes_decrypt, aes_encrypt

HOST = "127.0.0.1"
PORT = 5000

def start_server():
    print("Server started.")

    with open("server/server_cert.pem") as f:
        certificate = f.read()

    server_private = load_private("server/server_key.pem")

    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(1)

    conn, addr = s.accept()
    print("Client connected:", addr)

    # Step 1 — Send certificate
    conn.send(certificate.encode())

    # Step 2 — Receive encrypted AES key
    encrypted_key = conn.recv(4096)
    aes_key = server_private.decrypt(
        encrypted_key,
        padding.PKCS1v15()
    )
    print("Session key received.")

    # Step 3 — AES secure communication
    while True:
        enc = conn.recv(4096)
        if not enc:
            break
        msg = aes_decrypt(aes_key, enc)
        print("Client:", msg.decode())

        response = b"Message received!"
        conn.send(aes_encrypt(aes_key, response))

start_server()
