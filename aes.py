import itertools
import functools
import struct

# AES S-Box
s_box = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75]
]

# AES Round Constants
Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def sub_word(word):
    return [s_box[b >> 4][b & 0x0F] for b in word]

def rot_word(word):
    return word[1:] + word[:1]

def key_expansion(key):
    expanded_key = [list(row) for row in key]

    for i in range(4, 44):
        temp = expanded_key[i - 1]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= Rcon[(i // 4) - 1]
        new_word = [expanded_key[i - 4][j] ^ temp[j] for j in range(4)]
        expanded_key.append(new_word)

    return expanded_key

def sub_bytes(state):
    return [[s_box[b >> 4][b & 0x0F] for b in row] for row in state]

def shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]
    return state

def add_round_key(state, round_key):
    return [[state[i][j] ^ round_key[i][j] for j in range(4)] for i in range(4)]

def aes_encrypt_block(plaintext, key):
    state = [list(plaintext[i:i+4]) for i in range(0, 16, 4)]
    expanded_key = key_expansion(key)

    state = add_round_key(state, expanded_key[:4])

    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, expanded_key[round_num * 4:(round_num + 1) * 4])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, expanded_key[40:])

    return list(itertools.chain(*state))

def pad(plaintext):
    pad_len = 16 - (len(plaintext) % 16)
    return plaintext + bytes([pad_len] * pad_len)

def unpad(plaintext):
    return plaintext[:-plaintext[-1]]

class AES:
    def __init__(self, key, mode="ECB", iv=None):
        self.key = key
        self.mode = mode
        self.iv = iv if iv else [0] * 16

    def encrypt_ecb(self, plaintext):
        ciphertext = []
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            ciphertext.extend(aes_encrypt_block(block, self.key))
        return bytes(ciphertext)

    def encrypt_cbc(self, plaintext):
        ciphertext = []
        prev_block = self.iv
        for i in range(0, len(plaintext), 16):
            block = [plaintext[j] ^ prev_block[j] for j in range(16)]
            encrypted_block = aes_encrypt_block(block, self.key)
            prev_block = encrypted_block
            ciphertext.extend(encrypted_block)
        return bytes(ciphertext)

    def encrypt_cfb(self, plaintext):
        ciphertext = []
        prev_block = self.iv
        for i in range(0, len(plaintext), 16):
            encrypted_iv = aes_encrypt_block(prev_block, self.key)
            cipher_block = [plaintext[j] ^ encrypted_iv[j] for j in range(16)]
            prev_block = cipher_block
            ciphertext.extend(cipher_block)
        return bytes(ciphertext)

    def encrypt_ofb(self, plaintext):
        ciphertext = []
        prev_block = self.iv
        for i in range(0, len(plaintext), 16):
            encrypted_iv = aes_encrypt_block(prev_block, self.key)
            cipher_block = [plaintext[j] ^ encrypted_iv[j] for j in range(16)]
            prev_block = encrypted_iv
            ciphertext.extend(cipher_block)
        return bytes(ciphertext)

    def encrypt_ctr(self, plaintext):
        ciphertext = []
        counter = struct.unpack(">Q", bytes(self.iv[:8]))[0]
        nonce = struct.unpack(">Q", bytes(self.iv[8:]))[0]

        for i in range(0, len(plaintext), 16):
            counter_block = struct.pack(">QQ", nonce, counter)
            encrypted_counter = aes_encrypt_block(counter_block, self.key)
            cipher_block = [plaintext[j] ^ encrypted_counter[j] for j in range(16)]
            ciphertext.extend(cipher_block)
            counter += 1

        return bytes(ciphertext)

    def encrypt(self, plaintext):
        plaintext = pad(plaintext)
        if self.mode == "ECB":
            return self.encrypt_ecb(plaintext)
        elif self.mode == "CBC":
            return self.encrypt_cbc(plaintext)
        elif self.mode == "CFB":
            return self.encrypt_cfb(plaintext)
        elif self.mode == "OFB":
            return self.encrypt_ofb(plaintext)
        elif self.mode == "CTR":
            return self.encrypt_ctr(plaintext)
        else:
            raise ValueError("Unsupported Mode!")

# Example Usage
plaintext = b"Hello, AES Modes!"
key = [[0x2B, 0x7E, 0x15, 0x16],
       [0x28, 0xAE, 0xD2, 0xA6],
       [0xAB, 0xF7, 0x3D, 0x4D],
       [0x4D, 0xAD, 0xFA, 0x3E]]

aes = AES(key, mode="CBC", iv=[0] * 16)
ciphertext = aes.encrypt(plaintext)
print("Ciphertext:", ciphertext.hex())