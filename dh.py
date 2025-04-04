# Simple Diffie-Hellman Key Exchange in Python

# Public parameters (agreed upon by both parties)
P = 23    # A prime number
G = 5     # A primitive root modulo P

print("Publicly Shared: Prime (P) =", P, "and Base (G) =", G)

# Alice chooses a private key
a = 6  # Alice's private key
A = (G ** a) % P  # Alice's public value

# Bob chooses a private key
b = 15  # Bob's private key
B = (G ** b) % P  # Bob's public value

print("Alice's Public Key (A):", A)
print("Bob's Public Key (B):", B)

# Exchange happens (A and B are shared), then they compute the shared secret
shared_secret_alice = (B ** a) % P
shared_secret_bob = (A ** b) % P

print("Alice's Shared Secret:", shared_secret_alice)
print("Bob's Shared Secret:  ", shared_secret_bob)
