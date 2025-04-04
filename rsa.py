# Helper function to compute GCD
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Helper function to compute modular inverse using Extended Euclidean Algorithm
def mod_inverse(e, phi):
    a, b, x0, x1 = phi, e, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
    return x0 % phi

# User provides p, q, and e manually
def rsa_setup(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime with phi(n)")
    
    d = mod_inverse(e, phi)
    return (e, n), (d, n)  # Public and Private keys

# Encrypt message (convert text to numbers)
def encrypt(message, key):
    e, n = key
    return [pow(ord(char), e, n) for char in message]

# Decrypt message (convert numbers back to text)
def decrypt(ciphertext, key):
    d, n = key
    return ''.join(chr(pow(num, d, n)) for num in ciphertext)

# Example Usage (User-defined keys)
p = 61  # User provides prime p
q = 53  # User provides prime q
e = 17  # User provides public exponent e

public_key, private_key = rsa_setup(p, q, e)

message = "Hello"
ciphertext = encrypt(message, public_key)
decrypted_text = decrypt(ciphertext, private_key)

print("Public Key:", public_key)
print("Private Key:", private_key)
print("Original Message:", message)
print("Ciphertext:", ciphertext)
print("Decrypted Text:", decrypted_text)
