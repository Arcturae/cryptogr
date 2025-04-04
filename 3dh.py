# Public parameters
P = 23    # A prime number
G = 5     # A primitive root modulo P

print("Publicly Shared: Prime (P) =", P, "and Base (G) =", G)

# Each person chooses a private key
a = 6   # Alice's private key
b = 15  # Bob's private key
c = 13  # Charlie's private key

# Compute their public keys
A = pow(G, a, P)  # Alice's public value
B = pow(G, b, P)  # Bob's public value
C = pow(G, c, P)  # Charlie's public value

print("\nPublic Keys:")
print("Alice (A):", A)
print("Bob (B):  ", B)
print("Charlie (C):", C)

# Each computes an intermediate shared key with one other person

# Alice computes (B^a mod P)
AB = pow(B, a, P)
# Bob computes (C^b mod P)
BC = pow(C, b, P)
# Charlie computes (A^c mod P)
CA = pow(A, c, P)

# Now each computes the final shared key using the intermediate value

# Alice: (BC)^a mod P = ( (C^b)^a ) mod P
K_Alice = pow(BC, a, P)

# Bob: (CA)^b mod P = ( (A^c)^b ) mod P
K_Bob = pow(CA, b, P)

# Charlie: (AB)^c mod P = ( (B^a)^c ) mod P
K_Charlie = pow(AB, c, P)

print("\nShared Secrets:")
print("Alice's key:  ", K_Alice)
print("Bob's key:    ", K_Bob)
print("Charlie's key:", K_Charlie)
