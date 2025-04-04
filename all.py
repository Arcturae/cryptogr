import string

def caesar_encrypt(message, shift):
    encrypted = ''
    for c in message:
        if c.isalpha():
            base = 'a' if c.islower() else 'A'
            encrypted += chr((ord(c) - ord(base) + shift) % 26 + ord(base))
        else:
            encrypted += c
    return encrypted

def caesar_decrypt(message, shift):
    return caesar_encrypt(message, -shift)

def generate_repeating_key(key, message_length):
    return (key * (message_length // len(key)) + key[:message_length % len(key)])

def vigenere_encrypt(message, key):
    actual_key = generate_repeating_key(key, len(message))
    encrypted = ''
    for c, k in zip(message, actual_key):
        if c.isalpha():
            base = 'a' if c.islower() else 'A'
            encrypted += chr((ord(c) - ord(base) + ord(k.upper()) - ord('A')) % 26 + ord(base))
        else:
            encrypted += c
    return encrypted

def vigenere_decrypt(message, key):
    actual_key = generate_repeating_key(key, len(message))
    decrypted = ''
    for c, k in zip(message, actual_key):
        if c.isalpha():
            base = 'a' if c.islower() else 'A'
            decrypted += chr((ord(c) - ord(base) - (ord(k.upper()) - ord('A')) + 26) % 26 + ord(base))
        else:
            decrypted += c
    return decrypted

def vernam_encrypt(message, key):
    if len(key) < len(message):
        raise ValueError("Key length must be at least equal to the message length.")
    return ''.join(chr(ord(m) ^ ord(k) & 0x7F) for m, k in zip(message, key))

def vernam_decrypt(cipher, key):
    return vernam_encrypt(cipher, key)  # XOR is symmetric

def remove_duplicates(s):
    result = ''
    for c in s:
        if c not in result:
            result += c
    return result

def generate_key_matrix(key):
    key = remove_duplicates(key.replace('j', 'i').lower())
    alphabet = 'abcdefghiklmnopqrstuvwxyz'
    key += ''.join(c for c in alphabet if c not in key)
    return [list(key[i:i+5]) for i in range(0, 25, 5)]

def find_position(matrix, ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j
    return -1, -1

def preprocess_plaintext(text):
    text = ''.join(filter(str.isalpha, text)).lower().replace('j', 'i')
    processed = ''
    i = 0
    while i < len(text):
        processed += text[i]
        if i+1 < len(text) and text[i] == text[i+1]:
            processed += 'x'
        elif i+1 < len(text):
            processed += text[i+1]
            i += 1
        i += 1
    if len(processed) % 2 != 0:
        processed += 'x'
    return processed

def encrypt_pair(matrix, a, b):
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)
    if r1 == r2:
        return matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
    elif c1 == c2:
        return matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
    else:
        return matrix[r1][c2] + matrix[r2][c1]

def decrypt_pair(matrix, a, b):
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)
    if r1 == r2:
        return matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]
    elif c1 == c2:
        return matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]
    else:
        return matrix[r1][c2] + matrix[r2][c1]

def playfair_encrypt(text, key):
    matrix = generate_key_matrix(key)
    text = preprocess_plaintext(text)
    return ''.join(encrypt_pair(matrix, text[i], text[i+1]) for i in range(0, len(text), 2))

def playfair_decrypt(text, key):
    matrix = generate_key_matrix(key)
    return ''.join(decrypt_pair(matrix, text[i], text[i+1]) for i in range(0, len(text), 2))

def mod(a, b):
    return (a % b + b) % b

def determinant(matrix, n):
    if n == 1:
        return matrix[0][0]
    det = 0
    for x in range(n):
        submatrix = [[matrix[i][j] for j in range(n) if j != x] for i in range(1, n)]
        sign = 1 if x % 2 == 0 else -1
        det += sign * matrix[0][x] * determinant(submatrix, n - 1)
    return det

def modular_inverse(a, m):
    a = mod(a, m)
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse.")

def matrix_inverse(matrix, n):
    det = determinant(matrix, n)
    det_inv = modular_inverse(det, 26)
    adjoint = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [[matrix[x][y] for y in range(n) if y != j] for x in range(n) if x != i]
            cofactor = ((-1)**(i + j)) * determinant(minor, n - 1)
            adjoint[j][i] = mod(cofactor * det_inv, 26)
    return adjoint

def hill_encrypt(text, key):
    n = len(key)
    text = ''.join(filter(str.isalpha, text)).lower()
    while len(text) % n != 0:
        text += 'x'
    ciphertext = ''
    for i in range(0, len(text), n):
        for row in key:
            total = sum(row[j] * (ord(text[i + j]) - ord('a')) for j in range(n))
            ciphertext += chr(total % 26 + ord('a'))
    return ciphertext

def hill_decrypt(ciphertext, key):
    n = len(key)
    inv_key = matrix_inverse(key, n)
    plaintext = ''
    for i in range(0, len(ciphertext), n):
        for row in inv_key:
            total = sum(row[j] * (ord(ciphertext[i + j]) - ord('a')) for j in range(n))
            plaintext += chr(mod(total, 26) + ord('a'))
    return plaintext

def columnar_encrypt(plaintext, key):
    numCols = len(key)
    numRows = (len(plaintext) + numCols - 1) // numCols
    grid = [[' ']*numCols for _ in range(numRows)]
    for i, ch in enumerate(plaintext):
        grid[i // numCols][i % numCols] = ch
    order = sorted(range(numCols), key=lambda x: key[x])
    ciphertext = ''
    for col in order:
        for row in grid:
            if row[col] != ' ':
                ciphertext += row[col]
    return ciphertext

def columnar_decrypt(ciphertext, key):
    numCols = len(key)
    numRows = (len(ciphertext) + numCols - 1) // numCols
    colLens = [numRows] * numCols
    for i in range(numCols - len(ciphertext) % numCols):
        colLens[-(i + 1)] -= 1
    order = sorted(range(numCols), key=lambda x: key[x])
    grid = [''] * numCols
    idx = 0
    for col in order:
        grid[col] = ciphertext[idx:idx + colLens[col]]
        idx += colLens[col]
    plaintext = ''
    for row in range(numRows):
        for col in range(numCols):
            if row < len(grid[col]):
                plaintext += grid[col][row]
    return plaintext

def encrypt(message, choice):
    if choice == 1:
        return caesar_encrypt(message, 3)
    elif choice == 2:
        return vigenere_encrypt(message, "KEDAR")
    elif choice == 3:
        return vernam_encrypt(message, "KEDAR")
    elif choice == 4:
        return playfair_encrypt(message, "minimum")
    elif choice == 5:
        return hill_encrypt(message, [[2, 3], [1, 4]])
    elif choice == 6:
        return columnar_encrypt(message, "ZEBRAS")
    return message

def decrypt(message, choice):
    if choice == 1:
        return caesar_decrypt(message, 3)
    elif choice == 2:
        return vigenere_decrypt(message, "KEDAR")
    elif choice == 3:
        return vernam_decrypt(message, "KEDAR")
    elif choice == 4:
        return playfair_decrypt(message, "minimum")
    elif choice == 5:
        return hill_decrypt(message, [[2, 3], [1, 4]])
    elif choice == 6:
        return columnar_decrypt(message, "ZEBRAS")
    return message
