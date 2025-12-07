from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # PKCS7 padding
    pad_len = 16 - len(plaintext) % 16
    plaintext += bytes([pad_len]) * pad_len

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()

    pad_len = padded[-1]
    return padded[:-pad_len]
