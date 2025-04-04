# Public parameters
P = 23
G = 5

print("Publicly Shared: Prime (P) =", P, "and Base (G) =", G)

# Alice's private and public key
a = 6
A = pow(G, a, P)

# Bob's private and public key
b = 15
B = pow(G, b, P)

# Mallory (MITM attacker) has her own private key
m = 13

# Mallory intercepts A and B and replaces them with her own fake public keys
# She sends M1 to Bob instead of A
# She sends M2 to Alice instead of B
M1 = pow(G, m, P)  # Mallory's public key to Bob
M2 = pow(G, m, P)  # Mallory's public key to Alice

print("\n--- Mallory intercepts and modifies ---")
print("Alice sends A =", A, "but Mallory sends M1 =", M1, "to Bob")
print("Bob sends B =", B, "but Mallory sends M2 =", M2, "to Alice")

# Now Alice thinks M2 is Bob's public key and computes shared key
K_Alice = pow(M2, a, P)

# Bob thinks M1 is Alice's public key and computes shared key
K_Bob = pow(M1, b, P)

# Mallory computes both keys to impersonate both sides
K_with_Alice = pow(A, m, P)
K_with_Bob = pow(B, m, P)

print("\n--- Shared Secrets ---")
print("Alice's key (with Mallory):", K_Alice)
print("Bob's key (with Mallory):  ", K_Bob)
print("Mallory's key with Alice:  ", K_with_Alice)
print("Mallory's key with Bob:    ", K_with_Bob)

# Mallory can now decrypt and re-encrypt messages between Alice and Bob
