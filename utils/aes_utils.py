from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)
