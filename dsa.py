import random
from hashlib import sha1

# DSA parameters (small for example; insecure for real use)
p = 8081  # large prime
q = 101   # prime divisor of p-1
g = pow(2, (p-1)//q, p)  # generator

# Key Generation
def generate_keys():
    x = random.randint(1, q-1)           # private key
    y = pow(g, x, p)                     # public key
    return x, y

# Hash function
def H(msg):
    return int(sha1(msg.encode()).hexdigest(), 16)

# Signature Generation
def sign(msg, x):
    h = H(msg) % q
    while True:
        k = random.randint(1, q-1)
        r = pow(g, k, p) % q
        if r == 0:
            continue
        k_inv = pow(k, -1, q)
        s = (k_inv * (h + x * r)) % q
        if s != 0:
            break
    return r, s

# Signature Verification
def verify(msg, r, s, y):
    if not (0 < r < q and 0 < s < q):
        return False
    h = H(msg) % q
    w = pow(s, -1, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

# Example usage
if __name__ == "__main__":
    msg = "dsa test message"
    x, y = generate_keys()
    r, s = sign(msg, x)
    print(f"Signature: r={r}, s={s}")
    print("Valid Signature?" , verify(msg, r, s, y))
