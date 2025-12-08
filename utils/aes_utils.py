import os

# Constants from aes.ipynb
SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# Inverse S-box
INV_SBOX = [0]*256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Round constants for AES-128 (Rcon)
RCON = [
    0x00000000,
    0x01000000,0x02000000,0x04000000,0x08000000,
    0x10000000,0x20000000,0x40000000,0x80000000,
    0x1B000000,0x36000000
]

# Helper functions
def gmul(a, b):
    """Galois field multiplication of two bytes"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p

def rot_word(word):
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF)

def sub_word(word):
    return ((SBOX[(word>>24)&0xFF] << 24) |
            (SBOX[(word>>16)&0xFF] << 16) |
            (SBOX[(word>>8)&0xFF] << 8) |
            SBOX[word & 0xFF])

def key_expansion(key):
    """Generate 11 round keys (AES-128)"""
    Nk, Nb, Nr = 4, 4, 10
    w = [0]*(Nb*(Nr+1))
    for i in range(Nk):
        w[i] = (key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3]
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ RCON[i//Nk]
        w[i] = w[i-Nk] ^ temp
    roundkeys = []
    for r in range(Nr+1):
        rk = []
        for c in range(4):
            word = w[r*4 + c]
            rk += [(word>>24)&0xFF, (word>>16)&0xFF, (word>>8)&0xFF, word&0xFF]
        roundkeys.append(rk)
    return roundkeys

def add_round_key(state, rk):
    return [s ^ k for s, k in zip(state, rk)]

def sub_bytes(state):
    return [SBOX[b] for b in state]

def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]

def shift_rows(s):
    t = [0]*16
    for c in range(4):
        t[0+4*c] = s[0+4*c]
        t[1+4*c] = s[1+4*((c+1)%4)]
        t[2+4*c] = s[2+4*((c+2)%4)]
        t[3+4*c] = s[3+4*((c+3)%4)]
    return t

def inv_shift_rows(s):
    t = [0]*16
    for c in range(4):
        t[0+4*c] = s[0+4*c]
        t[1+4*c] = s[1+4*((c-1)%4)]
        t[2+4*c] = s[2+4*((c-2)%4)]
        t[3+4*c] = s[3+4*((c-3)%4)]
    return t

def mix_columns(s):
    t = [0]*16
    for c in range(4):
        a = [s[r+4*c] for r in range(4)]
        t[0+4*c] = gmul(2, a[0]) ^ gmul(3, a[1]) ^ a[2] ^ a[3]
        t[1+4*c] = a[0] ^ gmul(2, a[1]) ^ gmul(3, a[2]) ^ a[3]
        t[2+4*c] = a[0] ^ a[1] ^ gmul(2, a[2]) ^ gmul(3, a[3])
        t[3+4*c] = gmul(3, a[0]) ^ a[1] ^ a[2] ^ gmul(2, a[3])
    return t

def inv_mix_columns(s):
    t = [0]*16
    for c in range(4):
        a = [s[r+4*c] for r in range(4)]
        t[0+4*c] = gmul(0x0e, a[0]) ^ gmul(0x0b, a[1]) ^ gmul(0x0d, a[2]) ^ gmul(0x09, a[3])
        t[1+4*c] = gmul(0x09, a[0]) ^ gmul(0x0e, a[1]) ^ gmul(0x0b, a[2]) ^ gmul(0x0d, a[3])
        t[2+4*c] = gmul(0x0d, a[0]) ^ gmul(0x09, a[1]) ^ gmul(0x0e, a[2]) ^ gmul(0x0b, a[3])
        t[3+4*c] = gmul(0x0b, a[0]) ^ gmul(0x0d, a[1]) ^ gmul(0x09, a[2]) ^ gmul(0x0e, a[3])
    return t

# AES core
def cipher(pt, rks):
    """AES encryption of a single 16-byte block"""
    s = add_round_key(pt, rks[0])
    for r in range(1, 10):
        s = sub_bytes(s)
        s = shift_rows(s)
        s = mix_columns(s)
        s = add_round_key(s, rks[r])
    s = sub_bytes(s)
    s = shift_rows(s)
    s = add_round_key(s, rks[10])
    return s

def inv_cipher(ct, rks):
    """AES decryption of a single 16-byte block"""
    s = add_round_key(ct, rks[10])
    for r in range(9, 0, -1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, rks[r])
        s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = add_round_key(s, rks[0])
    return s

# PKCS7 padding
def pad(data, block_size=16):
    """Add PKCS7 padding"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """Remove PKCS7 padding"""
    pad_len = data[-1]
    return data[:-pad_len]

# CBC mode encryption/decryption
def aes_encrypt(key, plaintext):
    """Encrypt using AES-128 in CBC mode"""
    # Convert key to list of integers
    key_list = list(key[:16])  # Use first 16 bytes for AES-128
    
    # Generate random IV
    iv = list(os.urandom(16))
    
    # Expand key
    rks = key_expansion(key_list)
    
    # Pad plaintext
    padded = pad(plaintext)
    
    # Encrypt in CBC mode
    ciphertext = []
    prev_block = iv
    
    for i in range(0, len(padded), 16):
        block = list(padded[i:i+16])
        # XOR with previous ciphertext block (or IV for first block)
        xored = [b ^ p for b, p in zip(block, prev_block)]
        # Encrypt block
        encrypted = cipher(xored, rks)
        ciphertext.extend(encrypted)
        prev_block = encrypted
    
    # Return IV + ciphertext as bytes
    return bytes(iv) + bytes(ciphertext)

def aes_decrypt(key, ciphertext):
    """Decrypt using AES-128 in CBC mode"""
    # Extract IV and ciphertext
    iv = list(ciphertext[:16])
    ct = ciphertext[16:]
    
    # Convert key to list of integers
    key_list = list(key[:16])  # Use first 16 bytes for AES-128
    
    # Expand key
    rks = key_expansion(key_list)
    
    # Decrypt in CBC mode
    plaintext = []
    prev_block = iv
    
    for i in range(0, len(ct), 16):
        block = list(ct[i:i+16])
        # Decrypt block
        decrypted = inv_cipher(block, rks)
        # XOR with previous ciphertext block (or IV for first block)
        xored = [d ^ p for d, p in zip(decrypted, prev_block)]
        plaintext.extend(xored)
        prev_block = block
    
    # Remove padding and return
    return unpad(bytes(plaintext))
