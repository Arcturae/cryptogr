import struct

# SHA-1 Padding
def sha1_padding(message):
    original_len = len(message) * 8
    message += b'\x80'  # Append a single 1 bit (0x80)
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'  # Pad with zeros
    message += struct.pack('>Q', original_len)  # Append original length as 64-bit big-endian
    return message

# Left rotate function
def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

# SHA-1 Compression Function
def sha1_process_chunk(chunk, h):
    w = list(struct.unpack('>16I', chunk)) + [0] * 64
    for i in range(16, 80):
        w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

    a, b, c, d, e = h
    for i in range(80):
        if i < 20:
            f = (b & c) | (~b & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        a, b, c, d, e = temp, a, left_rotate(b, 30), c, d

    return [(h[i] + v) & 0xFFFFFFFF for i, v in enumerate([a, b, c, d, e])]

# SHA-1 Main Function
def sha1(message):
    message = sha1_padding(message)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    
    for i in range(0, len(message), 64):
        h = sha1_process_chunk(message[i:i+64], h)

    return ''.join(f'{v:08x}' for v in h)

# Example Usage
message = b"Hello, World!"
hash_value = sha1(message)
print("SHA-1 Hash:", hash_value)
