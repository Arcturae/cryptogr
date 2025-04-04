import struct
import itertools

# MD5 Constants
s = [
    7, 12, 17, 22,  5,  9, 14, 20,  4, 11, 16, 23,  6, 10, 15, 21
] * 4

K = [int(abs(2**32 * abs(itertools.cycle([i]))) % 2**32) for i in range(64)]

# Helper Functions
def left_rotate(x, amount):
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

def md5_padding(message):
    original_len = len(message) * 8
    message += b'\x80'  # Append a single 1 bit (0x80)
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'  # Pad with zeros
    message += struct.pack('<Q', original_len)  # Append original length as 64-bit little-endian
    return message

def md5_process_chunk(chunk, h):
    a, b, c, d = h
    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & c)
            g = (5*i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3*i + 5) % 16
        else:
            f = c ^ (b | ~d)
            g = (7*i) % 16
        f = (f + a + K[i] + struct.unpack('<I', chunk[4*g:4*g+4])[0]) & 0xFFFFFFFF
        a, d, c, b = d, c, b, (b + left_rotate(f, s[i])) & 0xFFFFFFFF
    return [(h[i] + v) & 0xFFFFFFFF for i, v in enumerate([a, b, c, d])]

def md5(message):
    message = md5_padding(message)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for i in range(0, len(message), 64):
        h = md5_process_chunk(message[i:i+64], h)
    return ''.join(f'{v:08x}' for v in struct.unpack('<4I', struct.pack('<4I', *h)))

# Example Usage
message = b"Hello, World!"
hash_value = md5(message)
print("MD5 Hash:", hash_value)
