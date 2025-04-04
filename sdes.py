import itertools

# Permutation tables
P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
P8 = [5, 2, 6, 3, 7, 4, 9, 8]
IP = [1, 5, 2, 0, 3, 7, 4, 6]
IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]
EP = [3, 0, 1, 2, 1, 2, 3, 0]
P4 = [1, 3, 2, 0]

# S-Boxes
S1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
S2 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 2], [2, 1, 0, 3]]

def permute(bits, table):
    return [bits[i] for i in table]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def key_schedule(key):
    key = permute(key, P10)
    left, right = key[:5], key[5:]
    left, right = left_shift(left, 1), left_shift(right, 1)
    k1 = permute(left + right, P8)
    left, right = left_shift(left, 2), left_shift(right, 2)
    k2 = permute(left + right, P8)
    return k1, k2

def s_box_lookup(sbox, bits):
    row = (bits[0] << 1) | bits[3]
    col = (bits[1] << 1) | bits[2]
    val = sbox[row][col]
    return [(val >> 1) & 1, val & 1]

def fk(bits, key):
    left, right = bits[:4], bits[4:]
    expanded_right = permute(right, EP)
    xor_result = [a ^ b for a, b in zip(expanded_right, key)]
    left_sbox = s_box_lookup(S1, xor_result[:4])
    right_sbox = s_box_lookup(S2, xor_result[4:])
    sbox_out = permute(left_sbox + right_sbox, P4)
    return [a ^ b for a, b in zip(left, sbox_out)] + right

def sdes_encrypt(plaintext, key):
    k1, k2 = key_schedule(key)
    bits = permute(plaintext, IP)
    bits = fk(bits, k1)
    bits = bits[4:] + bits[:4]  # SW (Swap)
    bits = fk(bits, k2)
    return permute(bits, IP_inv)

def sdes_decrypt(ciphertext, key):
    k1, k2 = key_schedule(key)
    bits = permute(ciphertext, IP)
    bits = fk(bits, k2)
    bits = bits[4:] + bits[:4]  # SW (Swap)
    bits = fk(bits, k1)
    return permute(bits, IP_inv)

# Example Usage
plaintext = [1, 0, 1, 0, 0, 0, 1, 1]  # 8-bit plaintext
key = [1, 0, 1, 0, 0, 1, 0, 1, 1, 1]  # 10-bit key

ciphertext = sdes_encrypt(plaintext, key)
decrypted_text = sdes_decrypt(ciphertext, key)

print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted Text:", decrypted_text)
