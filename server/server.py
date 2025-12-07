import socket, json
from utils.crypto_utils import load_private
from utils.aes_utils import aes_encrypt, aes_decrypt
from cryptography.hazmat.primitives.asymmetric import padding

HOST = "127.0.0.1"
PORT = 5000

def start_server():
    print("Server started.")

    with open("server_cert.pem", "r") as f:
        cert_json = f.read()
    conn_socket = socket.socket()
    conn_socket.bind((HOST, PORT))
    conn_socket.listen(1)
    print(f"[SERVER] Listening on {HOST}:{PORT}...")
    conn, addr = conn_socket.accept()
    print("[SERVER] Client connected:", addr)

    # Step 1 — Send server certificate (JSON string)
    conn.send(cert_json.encode())

    # Step 2 — Receive AES session key
    server_private = load_private("server_key.pem")
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
