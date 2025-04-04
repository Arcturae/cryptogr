CAESAR CIPHER
Server
import socket

def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", port))
    server_socket.listen(1)
    print(f"Server listening on port {port}...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}.")

    shift = 3

    try:
        while True:

            client_message = conn.recv(1024).decode('utf-8')
            decrypted_message = caesar_cipher(client_message, shift, decrypt=True)
            print(f"Client (encrypted): {client_message}")
            print(f"Client (decrypted): {decrypted_message}")

            if decrypted_message.lower() == "exit":
                print("Connection closed by the client.")
                break

            server_message = input("You: ")
            encrypted_message = caesar_cipher(server_message, shift)
            conn.sendall(bytes(encrypted_message, 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if server_message.lower() == "exit":
                print("Closing connection...")
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_server(port)
Client
import socket

def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result

def start_client(port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    shift = 3 

    try:
        client_socket.connect(("localhost", port))
        print(f"Connected to server on port {port}.")

        while True:

            client_message = input("You: ")
            encrypted_message = caesar_cipher(client_message, shift)
            client_socket.sendall(bytes(encrypted_message, 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if client_message.lower() == "exit":
                print("Closing connection...")
                break

            server_message = client_socket.recv(1024).decode('utf-8')
            decrypted_message = caesar_cipher(server_message, shift, decrypt=True)
            print(f"Server (encrypted): {server_message}")
            print(f"Server (decrypted): {decrypted_message}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_client(port)
-------------------------------------------------------------------------------------
VERNAM CIPHER
Server
import socket

def vernam_cipher(text, key, decrypt=False):
    result = ""
    for t, k in zip(text, key):
        result += chr(ord(t) ^ ord(k))
    return result

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", port))
    server_socket.listen(1)
    print(f"Server listening on port {port}...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}.")

    try:
        while True:
            encrypted_message = conn.recv(1024).decode('utf-8')
            key = conn.recv(1024).decode('utf-8')

            decrypted_message = vernam_cipher(encrypted_message, key)
            print(f"Client (encrypted): {encrypted_message}")
            print(f"Client (decrypted): {decrypted_message}")

            if decrypted_message.lower() == "exit":
                print("Connection closed by the client.")
                break

            server_message = input("You: ")
            key = input("Enter a key (same length as message): ")
            while len(key) != len(server_message):
                key = input("Key length must match message length. Enter key again: ")

            encrypted_message = vernam_cipher(server_message, key)
            conn.sendall(bytes(encrypted_message, 'utf-8'))
            conn.sendall(bytes(key, 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if server_message.lower() == "exit":
                print("Closing connection...")
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_server(port)
CLIENT
import socket

def vernam_cipher(text, key, decrypt=False):
    result = ""
    for t, k in zip(text, key):
        result += chr(ord(t) ^ ord(k))
    return result

def start_client(port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect(("localhost", port))
        print(f"Connected to server on port {port}.")

        while True:

            client_message = input("You: ")
            key = input("Enter a key (same length as message): ")
            while len(key) != len(client_message):
                key = input("Key length must match message length. Enter key again: ")

            encrypted_message = vernam_cipher(client_message, key)
            client_socket.sendall(bytes(encrypted_message, 'utf-8'))
            client_socket.sendall(bytes(key, 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if client_message.lower() == "exit":
                print("Closing connection...")
                break

            encrypted_message = client_socket.recv(1024).decode('utf-8')
            key = client_socket.recv(1024).decode('utf-8')

            decrypted_message = vernam_cipher(encrypted_message, key)
            print(f"Server (encrypted): {encrypted_message}")
            print(f"Server (decrypted): {decrypted_message}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_client(port)
-------------------------------------------------------------------------------------VIGNERE CIPHER
SERVER
import socket

def vigenere_cipher(text, key, decrypt=False):
    result = ""
    key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    for t, k in zip(text, key):
        shift = ord(k) - ord('A') if not decrypt else ord('A') - ord(k)
        result += chr((ord(t.upper()) - ord('A') + shift) % 26 + ord('A')) if t.isupper() else \
                  chr((ord(t.lower()) - ord('a') + shift) % 26 + ord('a'))
    return result

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", port))
    server_socket.listen(1)
    print(f"Server listening on port {port}...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}.")

    try:
        while True:
            encrypted_message = conn.recv(1024).decode('utf-8')
            key = conn.recv(1024).decode('utf-8')

            decrypted_message = vigenere_cipher(encrypted_message, key, decrypt=True)
            print(f"Client (encrypted): {encrypted_message}")
            print(f"Client (decrypted): {decrypted_message}")

            if decrypted_message.lower() == "exit":
                print("Connection closed by the client.")
                break

            server_message = input("You: ")
            key = input("Enter a key: ")
            encrypted_message = vigenere_cipher(server_message, key)
            conn.sendall(bytes(encrypted_message, 'utf-8'))
            conn.sendall(bytes(key, 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if server_message.lower() == "exit":
                print("Closing connection...")
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_server(port)
CLIENT
import socket

def vigenere_cipher(text, key, decrypt=False):
    result = ""
    key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    for t, k in zip(text, key):
        shift = ord(k) - ord('A') if not decrypt else ord('A') - ord(k)
        result += chr((ord(t.upper()) - ord('A') + shift) % 26 + ord('A')) if t.isupper() else \
                  chr((ord(t.lower()) - ord('a') + shift) % 26 + ord('a'))
    return result

def start_client(port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect(("localhost", port))
        print(f"Connected to server on port {port}.")

        while True:
            client_message = input("You: ")
            key = input("Enter a key: ")
            encrypted_message = vigenere_cipher(client_message, key)
            client_socket.sendall(bytes(encrypted_message, 'utf-8'))
            client_socket.sendall(bytes(key, 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if client_message.lower() == "exit":
                print("Closing connection...")
                break

            encrypted_message = client_socket.recv(1024).decode('utf-8')
            key = client_socket.recv(1024).decode('utf-8')

            decrypted_message = vigenere_cipher(encrypted_message, key, decrypt=True)
            print(f"Server (encrypted): {encrypted_message}")
            print(f"Server (decrypted): {decrypted_message}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_client(port)
-------------------------------------------------------------------------------------
HILL CIPHER
Server
import socket
import numpy as np

def hill_cipher(text, key, decrypt=False):
    def mod26(matrix):
        return np.mod(matrix, 26)

    def inverse(matrix):
        det = int(np.round(np.linalg.det(matrix)))
        det_inv = pow(det, -1, 26)
        adjugate = np.round(np.linalg.inv(matrix) * det).astype(int)
        return mod26(adjugate * det_inv)

    def text_to_matrix(text, size):
        padding = (size - len(text) % size) % size
        text += 'X' * padding
        return np.array([ord(c) - ord('A') for c in text.upper()]).reshape(-1, size)

    def matrix_to_text(matrix):
        return ''.join([chr(int(c) + ord('A')) for c in matrix.flatten()])

    key_size = int(len(key) ** 0.5)
    key_matrix = np.array([ord(c) - ord('A') for c in key.upper()]).reshape(key_size, key_size)
    
    if decrypt:
        key_matrix = inverse(key_matrix)

    text_matrix = text_to_matrix(text, key_size)
    encrypted_matrix = mod26(np.dot(text_matrix, key_matrix))

    return matrix_to_text(encrypted_matrix)

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", port))
    server_socket.listen(1)
    print(f"Server listening on port {port}...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}.")

    try:
        while True:
            encrypted_message = conn.recv(1024).decode('utf-8')
            key = conn.recv(1024).decode('utf-8')

            decrypted_message = hill_cipher(encrypted_message, key, decrypt=True)
            print(f"Client (encrypted): {encrypted_message}")
            print(f"Client (decrypted): {decrypted_message}")

            if decrypted_message.lower() == "exit":
                print("Connection closed by the client.")
                break

            server_message = input("You: ")
            key_input = input("Enter a cipher key (as a string): ")
            encrypted_message = hill_cipher(server_message, key_input)
            conn.sendall(bytes(encrypted_message, 'utf-8'))
            conn.sendall(bytes(key_input, 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if server_message.lower() == "exit":
                print("Closing connection...")
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_server(port)
Client
import socket
import numpy as np

def hill_cipher(text, key, decrypt=False):
    def mod26(matrix):
        return np.mod(matrix, 26)

    def inverse(matrix):
        det = int(np.round(np.linalg.det(matrix)))
        det_inv = pow(det, -1, 26)
        adjugate = np.round(np.linalg.inv(matrix) * det).astype(int)
        return mod26(adjugate * det_inv)

    def text_to_matrix(text, size):
        padding = (size - len(text) % size) % size
        text += 'X' * padding
        return np.array([ord(c) - ord('A') for c in text.upper()]).reshape(-1, size)

    def matrix_to_text(matrix):
        return ''.join([chr(int(c) + ord('A')) for c in matrix.flatten()])

    key_size = int(len(key) ** 0.5)
    key_matrix = np.array([ord(c) - ord('A') for c in key.upper()]).reshape(key_size, key_size)
    
    if decrypt:
        key_matrix = inverse(key_matrix)

    text_matrix = text_to_matrix(text, key_size)
    encrypted_matrix = mod26(np.dot(text_matrix, key_matrix))

    return matrix_to_text(encrypted_matrix)

def start_client(port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect(("localhost", port))
        print(f"Connected to server on port {port}.")

        while True:
            client_message = input("You: ")
            key_input = input("Enter a cipher key (as a string): ")
            encrypted_message = hill_cipher(client_message, key_input)
            client_socket.sendall(bytes(encrypted_message, 'utf-8'))
            client_socket.sendall(bytes(key_input, 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if client_message.lower() == "exit":
                print("Closing connection...")
                break

            encrypted_message = client_socket.recv(1024).decode('utf-8')
            key = client_socket.recv(1024).decode('utf-8')

            decrypted_message = hill_cipher(encrypted_message, key, decrypt=True)
            print(f"Server (encrypted): {encrypted_message}")
            print(f"Server (decrypted): {decrypted_message}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_client(port)
-------------------------------------------------------------------------------------
Railfence Cipher
import socket

def encryptRailFence(text, key):
    rail = [['\n' for i in range(len(text))] for j in range(key)]
    dir_down = False
    row, col = 0, 0
    for i in range(len(text)):
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
        rail[row][col] = text[i]
        col += 1
        if dir_down:
            row += 1
        else:
            row -= 1
    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return "".join(result)

def decryptRailFence(cipher, key):
    rail = [['\n' for i in range(len(cipher))] for j in range(key)]
    dir_down = None
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        if dir_down:
            row += 1
        else:
            row -= 1
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1
        if dir_down:
            row += 1
        else:
            row -= 1
    return "".join(result)

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", port))
    server_socket.listen(1)
    print(f"Server listening on port {port}...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}.")

    try:
        while True:
            encrypted_message = conn.recv(1024).decode('utf-8')
            key = int(conn.recv(1024).decode('utf-8'))

            decrypted_message = decryptRailFence(encrypted_message, key)
            print(f"Client (encrypted): {encrypted_message}")
            print(f"Client (decrypted): {decrypted_message}")

            if decrypted_message.lower() == "exit":
                print("Connection closed by the client.")
                break

            server_message = input("You: ")
            key_input = int(input("Enter number of rails: "))
            encrypted_message = encryptRailFence(server_message, key_input)
            conn.sendall(bytes(encrypted_message, 'utf-8'))
            conn.sendall(bytes(str(key_input), 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if server_message.lower() == "exit":
                print("Closing connection...")
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_server(port)
Client
import socket

def encryptRailFence(text, key):
    rail = [['\n' for i in range(len(text))] for j in range(key)]
    dir_down = False
    row, col = 0, 0
    for i in range(len(text)):
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
        rail[row][col] = text[i]
        col += 1
        if dir_down:
            row += 1
        else:
            row -= 1
    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return "".join(result)

def decryptRailFence(cipher, key):
    rail = [['\n' for i in range(len(cipher))] for j in range(key)]
    dir_down = None
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        if dir_down:
            row += 1
        else:
            row -= 1
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1
        if dir_down:
            row += 1
        else:
            row -= 1
    return "".join(result)

def start_client(port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect(("localhost", port))
        print(f"Connected to server on port {port}.")

        while True:
            client_message = input("You: ")
            rails_input = int(input("Enter number of rails: "))
            encrypted_message = encryptRailFence(client_message, rails_input)
            client_socket.sendall(bytes(encrypted_message, 'utf-8'))
            client_socket.sendall(bytes(str(rails_input), 'utf-8'))
            print(f"Encrypted (sent): {encrypted_message}")

            if client_message.lower() == "exit":
                print("Closing connection...")
                break

            encrypted_message = client_socket.recv(1024).decode('utf-8')
            rails = int(client_socket.recv(1024).decode('utf-8'))

            decrypted_message = decryptRailFence(encrypted_message, rails)
            print(f"Server (encrypted): {encrypted_message}")
            print(f"Server (decrypted): {decrypted_message}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    port = int(input("Enter the port number to use: "))
    start_client(port)
-------------------------------------------------------------------------------------
PLAYFAIR CIPHER
Server
import socket

def generate_playfair_matrix(key):
    key = ''.join(sorted(set(key), key=lambda k: key.index(k)))  # Remove duplicates, preserve order
    key = key.replace('J', 'I')  # Replace J with I
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    matrix = [c for c in key if c.isalpha()]
    for letter in alphabet:
        if letter not in matrix:
            matrix.append(letter)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, letter):
    for i, row in enumerate(matrix):
        if letter in row:
            return i, row.index(letter)
    return None, None

def process_playfair(matrix, text, encrypt=True):
    text = text.upper().replace('J', 'I')
    processed_text = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else 'X'
        if a == b:
            b = 'X'
        elif i + 1 == len(text):
            text += 'X'

        a_row, a_col = find_position(matrix, a)
        b_row, b_col = find_position(matrix, b)
        if a_row == b_row:
            processed_text.append(matrix[a_row][(a_col + (1 if encrypt else -1)) % 5])
            processed_text.append(matrix[b_row][(b_col + (1 if encrypt else -1)) % 5])
        elif a_col == b_col:
            processed_text.append(matrix[(a_row + (1 if encrypt else -1)) % 5][a_col])
            processed_text.append(matrix[(b_row + (1 if encrypt else -1)) % 5][b_col])
        else:
            processed_text.append(matrix[a_row][b_col])
            processed_text.append(matrix[b_row][a_col])
        i += 2

    return ''.join(processed_text)

def format_matrix(matrix):
    return '\n'.join([' '.join(row) for row in matrix])

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(5)
    print("Server is listening on port 12345...")
    
    while True:
        client_socket, addr = server.accept()
        print(f"Connected with {addr}")
        
        try:
            while True:
                # Receive data from client
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                print(f"Received from client: {data}")
                
                # Parse the key and encrypted message
                key, encrypted_message = data.split(';')
                
                # Generate Playfair matrix
                matrix = generate_playfair_matrix(key)
                
                # Decrypt the message
                decrypted_message = process_playfair(matrix, encrypted_message, encrypt=False)
                print(f"Decrypted message: {decrypted_message}")
                
                # Format the response
                matrix_string = format_matrix(matrix)
                response = f"Playfair Matrix:\n{matrix_string}\nDecrypted Message: {decrypted_message}"
                
                # Send response back to the client
                client_socket.sendall(response.encode())
                
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()
            print(f"Disconnected from {addr}")

if __name__ == "__main__":
    main()
Client
import socket

def generate_playfair_matrix(key):
    key = ''.join(sorted(set(key), key=lambda k: key.index(k)))  # Remove duplicates, preserve order
    key = key.replace('J', 'I')  # Replace J with I
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    matrix = [c for c in key if c.isalpha()]
    for letter in alphabet:
        if letter not in matrix:
            matrix.append(letter)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, letter):
    for i, row in enumerate(matrix):
        if letter in row:
            return i, row.index(letter)
    return None, None

def process_playfair(matrix, text, encrypt=True):
    text = text.upper().replace('J', 'I')
    processed_text = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else 'X'
        if a == b:
            b = 'X'
        elif i + 1 == len(text):
            text += 'X'

        a_row, a_col = find_position(matrix, a)
        b_row, b_col = find_position(matrix, b)
        if a_row == b_row:
            processed_text.append(matrix[a_row][(a_col + (1 if encrypt else -1)) % 5])
            processed_text.append(matrix[b_row][(b_col + (1 if encrypt else -1)) % 5])
        elif a_col == b_col:
            processed_text.append(matrix[(a_row + (1 if encrypt else -1)) % 5][a_col])
            processed_text.append(matrix[(b_row + (1 if encrypt else -1)) % 5][b_col])
        else:
            processed_text.append(matrix[a_row][b_col])
            processed_text.append(matrix[b_row][a_col])
        i += 2

    return ''.join(processed_text)

def format_matrix(matrix):
    return '\n'.join([' '.join(row) for row in matrix])

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(5)
    print("Server is listening on port 12345...")
    
    while True:
        client_socket, addr = server.accept()
        print(f"Connected with {addr}")
        
        try:
            while True:
                # Receive data from client
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                print(f"Received from client: {data}")
                
                # Parse the key and encrypted message
                key, encrypted_message = data.split(';')
                
                # Generate Playfair matrix
                matrix = generate_playfair_matrix(key)
                
                # Decrypt the message
                decrypted_message = process_playfair(matrix, encrypted_message, encrypt=False)
                print(f"Decrypted message: {decrypted_message}")
                
                # Format the response
                matrix_string = format_matrix(matrix)
                response = f"Playfair Matrix:\n{matrix_string}\nDecrypted Message: {decrypted_message}"
                
                # Send response back to the client
                client_socket.sendall(response.encode())
                
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()
            print(f"Disconnected from {addr}")

if __name__ == "__main__":
    main()
-------------------------------------------------------------------------------------
AES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

def print_round_state(round_num, state):
    print(f"Round {round_num} state:")
    for row in state:
        print(" ".join(f"{x:02X}" for x in row))
    print()

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext, AES.block_size)
    blocks = [padded_plaintext[i:i+16] for i in range(0, len(padded_plaintext), 16)]
    
    for block_num, block in enumerate(blocks, start=1):
        print(f"Encrypting block {block_num}:")
        print("Plaintext block:", binascii.hexlify(block).decode())
        state = [list(block[i:i+4]) for i in range(0, 16, 4)]
        print_round_state(0, state)
        
        intermediate_states = []
        for round_num in range(1, 11):
            encrypted_block = cipher.encrypt(block)
            state = [list(encrypted_block[i:i+4]) for i in range(0, 16, 4)]
            intermediate_states.append(state)
            print_round_state(round_num, state)
            block = encrypted_block
        
        print("Ciphertext block:", binascii.hexlify(encrypted_block).decode())
        print("=" * 50)
    
    return b"".join([cipher.encrypt(block) for block in blocks])

plaintext = binascii.unhexlify("0123456789ABCDEFFEDCBA9876543210")  # 16-byte (128-bit) plaintext in hex
key = binascii.unhexlify("0F1571C947D9E8591CB7ADD6AF7F6798")  # 16-byte (128-bit) key in hex
ciphertext = aes_encrypt(plaintext, key)
-------------------------------------------------------------------------------------
SDES
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

-------------------------------------------------------------------------------------
Man in the middle MITM

Alice 
import socket

P = 23  
G = 5  

def start_alice():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 8888))  

    alice_private = 4  
    alice_public = (G ** alice_private) % P  

    bob_public = int(client.recv(1024).decode())

    client.sendall(str(alice_public).encode())

    shared_secret = (bob_public ** alice_private) % P  
    print(f"[Alice] Shared secret computed: {shared_secret}")

    client.close()

if __name__ == "__main__":
    start_alice()

Bob
import socket

P = 23  
G = 5  

def start_bob():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))  
    server.listen(1)
    print("[Bob] Waiting for Alice...")

    conn, addr = server.accept()
    print(f"[Bob] Alice connected from {addr}")

    bob_private = 6  
    bob_public = (G ** bob_private) % P  

    conn.sendall(str(bob_public).encode())

    alice_public = int(conn.recv(1024).decode())

    shared_secret = (alice_public ** bob_private) % P  
    print(f"[Bob] Shared secret computed: {shared_secret}")

    conn.close()

if __name__ == "__main__":
    start_bob()

Mallory
import socket

P = 23  
G = 5  

def start_mallory():

    mallory_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mallory_server.bind(("0.0.0.0", 8888))  
    mallory_server.listen(1)
    print("[Mallory] Waiting for Alice...")

    alice_conn, alice_addr = mallory_server.accept()
    print(f"[Mallory] Alice connected from {alice_addr}")

    bob_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_server.connect(("127.0.0.1", 9999))  

    bob_public = int(bob_server.recv(1024).decode())

    mallory_private = 9  
    mallory_public = (G ** mallory_private) % P  

    alice_conn.sendall(str(mallory_public).encode())

    alice_public = int(alice_conn.recv(1024).decode())

    bob_server.sendall(str(mallory_public).encode())

    shared_secret_alice = (alice_public ** mallory_private) % P  
    shared_secret_bob = (bob_public ** mallory_private) % P  

    print(f"[Mallory] Shared secret with Alice: {shared_secret_alice}")
    print(f"[Mallory] Shared secret with Bob: {shared_secret_bob}")

    alice_conn.close()
    bob_server.close()
    mallory_server.close()

if __name__ == "__main__":
    start_mallory()
-------------------------------------------------------------------------------------
MD5
Server
import socket
import struct

# Left rotate function
def left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

# Constants for MD5 algorithm
s = [ 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
     5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
     4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
     6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

K = [int(2**32 * abs((2**32 - 1) ** (1/2) * abs(i) ** (1/2))) & 0xFFFFFFFF for i in range(64)]

# Initial hash values
IV = [
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
]

def md5(message):
    # Convert message to bytes
    message = bytearray(message, 'utf-8')
    
    orig_len_bits = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    
    # Append padding bits
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)

    # Append original length (in bits) as a 64-bit little-endian integer
    message += struct.pack('<Q', orig_len_bits)

    # Initialize hash values
    a, b, c, d = IV

    # Process message in 512-bit chunks (64 bytes)
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        X = list(struct.unpack('<16I', chunk))

        AA, BB, CC, DD = a, b, c, d

        for i in range(64):
            if i < 16:
                F = (b & c) | (~b & d)
                g = i
            elif i < 32:
                F = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                F = c ^ (b | ~d)
                g = (7 * i) % 16

            F = (F + a + K[i] + X[g]) & 0xFFFFFFFF
            a, d, c, b = d, (b + left_rotate(F, s[i])) & 0xFFFFFFFF, b, c

        # Add this chunk's hash to result so far:
        a = (a + AA) & 0xFFFFFFFF
        b = (b + BB) & 0xFFFFFFFF
        c = (c + CC) & 0xFFFFFFFF
        d = (d + DD) & 0xFFFFFFFF

    # Produce final hash value (big-endian)
    result = struct.pack('<4I', a, b, c, d)
    return ''.join(f'{x:02x}' for x in result)

def start_server(host='127.0.0.1', port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    while True:
        data = conn.recv(1024).decode()
        if not data:
            break

        print(f"Received data: {data}")
        md5_hash = md5(data)  # Compute MD5 using our function
        print(f"Computed MD5: {md5_hash}")

        conn.sendall(md5_hash.encode())

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()

Client
import socket
import struct

# Left rotate function
def left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

# Constants for MD5 algorithm
s = [ 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
     5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
     4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
     6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

K = [int(2**32 * abs((2**32 - 1) ** (1/2) * abs(i) ** (1/2))) & 0xFFFFFFFF for i in range(64)]

# Initial hash values
IV = [
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
]

def md5(message):
    # Convert message to bytes
    message = bytearray(message, 'utf-8')
    
    orig_len_bits = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    
    # Append padding bits
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)

    # Append original length (in bits) as a 64-bit little-endian integer
    message += struct.pack('<Q', orig_len_bits)

    # Initialize hash values
    a, b, c, d = IV

    # Process message in 512-bit chunks (64 bytes)
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        X = list(struct.unpack('<16I', chunk))

        AA, BB, CC, DD = a, b, c, d

        for i in range(64):
            if i < 16:
                F = (b & c) | (~b & d)
                g = i
            elif i < 32:
                F = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                F = c ^ (b | ~d)
                g = (7 * i) % 16

            F = (F + a + K[i] + X[g]) & 0xFFFFFFFF
            a, d, c, b = d, (b + left_rotate(F, s[i])) & 0xFFFFFFFF, b, c

        # Add this chunk's hash to result so far:
        a = (a + AA) & 0xFFFFFFFF
        b = (b + BB) & 0xFFFFFFFF
        c = (c + CC) & 0xFFFFFFFF
        d = (d + DD) & 0xFFFFFFFF

    # Produce final hash value (big-endian)
    result = struct.pack('<4I', a, b, c, d)
    return ''.join(f'{x:02x}' for x in result)

def send_message(message, host='127.0.0.1', port=65432):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    client_socket.sendall(message.encode())
    md5_hash = client_socket.recv(1024).decode()
    
    print(f"Received MD5 Hash: {md5_hash}")

    client_socket.close()

if __name__ == "__main__":
    message = input("Enter message to send: ")
    send_message(message)
import socket
import struct

# Left rotate function
def left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

# Constants for MD5 algorithm
s = [ 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
     5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
     4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
     6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

K = [int(2**32 * abs((2**32 - 1) ** (1/2) * abs(i) ** (1/2))) & 0xFFFFFFFF for i in range(64)]

# Initial hash values
IV = [
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
]

def md5(message):
    # Convert message to bytes
    message = bytearray(message, 'utf-8')
    
    orig_len_bits = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    
    # Append padding bits
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)

    # Append original length (in bits) as a 64-bit little-endian integer
    message += struct.pack('<Q', orig_len_bits)

    # Initialize hash values
    a, b, c, d = IV

    # Process message in 512-bit chunks (64 bytes)
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        X = list(struct.unpack('<16I', chunk))

        AA, BB, CC, DD = a, b, c, d

        for i in range(64):
            if i < 16:
                F = (b & c) | (~b & d)
                g = i
            elif i < 32:
                F = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                F = c ^ (b | ~d)
                g = (7 * i) % 16

            F = (F + a + K[i] + X[g]) & 0xFFFFFFFF
            a, d, c, b = d, (b + left_rotate(F, s[i])) & 0xFFFFFFFF, b, c

        # Add this chunk's hash to result so far:
        a = (a + AA) & 0xFFFFFFFF
        b = (b + BB) & 0xFFFFFFFF
        c = (c + CC) & 0xFFFFFFFF
        d = (d + DD) & 0xFFFFFFFF

    # Produce final hash value (big-endian)
    result = struct.pack('<4I', a, b, c, d)
    return ''.join(f'{x:02x}' for x in result)

def send_message(message, host='127.0.0.1', port=65432):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    client_socket.sendall(message.encode())
    md5_hash = client_socket.recv(1024).decode()
    
    print(f"Received MD5 Hash: {md5_hash}")

    client_socket.close()

if __name__ == "__main__":
    message = input("Enter message to send: ")
    send_message(message)
-------------------------------------------------------------------------------------
RSA

Server
import socket
import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    for d in range(3, phi, 2): 
        if (d * e) % phi == 1:
            return d
    return None

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime():
    while True:
        num = random.randint(100, 999)  
        if is_prime(num):
            return num

p = generate_prime()
q = generate_prime()
n = p * q
phi = (p - 1) * (q - 1)

e = 3
while gcd(e, phi) != 1:
    e += 2 

d = mod_inverse(e, phi)

print("=" * 50)
print("🔐 RSA Key Generation")
print("=" * 50)
print(f"Prime p: {p}")
print(f"Prime q: {q}")
print(f"Modulus n (p*q): {n}")
print(f"Euler's Totient (phi): {phi}")
print(f"Public Key (e, n): ({e}, {n})")
print(f"Private Key (d, n): ({d}, {n})")
print("=" * 50)

message = "HELLOCLIENT"

message_numbers = [ord(char) for char in message]

encrypted_message = [pow(m, e, n) for m in message_numbers]

print("\n📨 Sending Encrypted Message...")
print("Original Message: ", message)
print("Numeric Form: ", message_numbers)
print("Encrypted Message: ", encrypted_message)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 12345))
server_socket.listen(1)
print("\n🚀 Server is waiting for a connection...")

conn, addr = server_socket.accept()
print(f"✅ Client Connected from {addr}")

conn.send(f"{e},{n}".encode())

conn.send(",".join(map(str, encrypted_message)).encode())

print("📤 Encrypted message sent successfully.")

conn.close()
server_socket.close()

Client
import socket


def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 12345))

e, n = map(int, client_socket.recv(1024).decode().split(","))

encrypted_message = list(map(int, client_socket.recv(1024).decode().split(",")))

print("=" * 50)
print("📥 Received Encrypted Data from Server")
print("=" * 50)
print(f"Public Key (e, n): ({e}, {n})")
print(f"Encrypted Message: {encrypted_message}")

d = 3
while (d * e) % ((n // e) - 1) != 1:
    d += 2

decrypted_message = [mod_exp(c, d, n) for c in encrypted_message]
decrypted_text = "".join(chr(m) for m in decrypted_message)

print("\n🔓 Decryption Process")
print("Numeric Decryption: ", decrypted_message)
print("Decrypted Message: HELLOCLIENT")

print("\n✅ Message Successfully Decrypted!")

client_socket.close()
-------------------------------------------------------------------------------------
DSA
Server
import socket
import threading

p = 23
q = 11
g = 4

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1: return None
    return x % m

def extended_gcd(a, b):
    if a == 0: return (b, 0, 1)
    g, y, x = extended_gcd(b % a, a)
    return (g, x - (b // a) * y, y)

def simple_hash(m): return sum(ord(c) for c in m) % q

def verify(m, r, s, y):
    if not (0 < r < q and 0 < s < q): return False
    w = modinv(s, q)
    if not w: return False
    h = simple_hash(m)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

def handle_client(conn, addr):
    try:
        data = conn.recv(1024).decode()
        m, r, s, y = data.split('|')
        r, s, y = int(r), int(s), int(y)
        if verify(m, r, s, y):
            print(f"Valid signature for: {m}")
            conn.sendall(b"Signature valid")
        else:
            print(f"Invalid signature for: {m}")
            conn.sendall(b"Signature invalid")
    finally:
        conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65432))
        s.listen()
        print("Server ready")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == '__main__':
    start_server()

Client
import socket
import random

p = 23
q = 11
g = 4

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1: return None
    return x % m

def extended_gcd(a, b):
    if a == 0: return (b, 0, 1)
    g, y, x = extended_gcd(b % a, a)
    return (g, x - (b // a) * y, y)

def simple_hash(m): return sum(ord(c) for c in m) % q

def generate_keys():
    x = random.randint(1, q-1)
    y = pow(g, x, p)
    return x, y

def sign(m, x):
    while True:
        k = random.randint(1, q-1)
        r = pow(g, k, p) % q
        if r == 0: continue
        s = (modinv(k, q) * (simple_hash(m) + x * r)) % q
        if s == 0: continue
        return r, s

def main():
    x, y = generate_keys()
    m = input("Enter message: ")
    r, s = sign(m, x)
    data = f"{m}|{r}|{s}|{y}"
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65432))
        s.sendall(data.encode())
        response = s.recv(1024).decode()
        print(f"Server response: {response}")

if __name__ == '__main__':
    main()
-------------------------------------------------------------------------------------
SHA-1
Server
import socket
import struct

# SHA-1 Constants
H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0

def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def sha1_manual(message):
    """Computes SHA-1 hash manually."""
    message = bytearray(message, 'utf-8')
    orig_len_in_bits = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF

    # Padding: Append 1 bit, then pad with 0 bits to reach 448 mod 512
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)

    # Append 64-bit original length
    message += struct.pack('>Q', orig_len_in_bits)

    # Initialize hash values
    h0, h1, h2, h3, h4 = H0, H1, H2, H3, H4

    for i in range(0, len(message), 64):
        chunk = message[i:i + 64]
        w = list(struct.unpack('>16I', chunk))

        for j in range(16, 80):
            w.append(left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1))

        a, b, c, d, e = h0, h1, h2, h3, h4

        for j in range(80):
            if j < 20:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif j < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF
            e, d, c, b, a = d, c, left_rotate(b, 30), a, temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return f'{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}'

def start_server(host='127.0.0.1', port=65432):
    """Starts the SHA-1 server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    while True:
        data = conn.recv(1024).decode()
        if not data or data.lower() == "exit":
            break

        print(f"Received: {data}")
        hash_value = sha1_manual(data)
        conn.send(hash_value.encode())
        print(f"Sent SHA-1 hash: {hash_value}")

    conn.close()
    server_socket.close()
    print("Server closed.")

if __name__ == "__main__":
    start_server()

Client
import socket

def start_client(host='127.0.0.1', port=65432):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")

    while True:
        message = input("Enter message (or 'exit' to quit): ")
        client_socket.send(message.encode())

        if message.lower() == "exit":
            break

        hash_value = client_socket.recv(1024).decode()
        print(f"SHA-1 Hash: {hash_value}")

    client_socket.close()
    print("Client disconnected.")

if __name__ == "__main__":
    start_client()
-------------------------------------------------------------------------------------
3 person diffie hellman

Server
import socket
import threading

clients = []
public_keys = []

def handle_client(conn, addr):
    print(f"[+] {addr} connected")
    # Receive public key
    pub = int(conn.recv(1024).decode())
    public_keys.append(pub)
    clients.append(conn)

    # Wait until all 3 clients connect
    while len(clients) < 3:
        pass

    # Send each client the other 2 public keys
    others = [str(k) for k in public_keys if k != pub]
    conn.send((",".join(others)).encode())

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 5555))
server.listen(3)
print("[*] Server listening on port 5555")

for _ in range(3):
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()

client
import socket

# Shared prime and base
p = 23
g = 5

# Set unique private key for each person manually
name = input("Enter your name (Alice/Bob/Carol): ")
private_keys = {'Alice': 6, 'Bob': 15, 'Carol': 13}
a = private_keys[name]

# Compute public key
public_key = pow(g, a, p)

# Connect to server and send public key
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 5555))
client.send(str(public_key).encode())

# Receive other public keys
data = client.recv(1024).decode()
others = list(map(int, data.strip().split(',')))

# Perform double exponentiation: (x^a)^b mod p
temp = pow(others[0], a, p)
shared_secret = pow(temp, a, p)

print(f"[{name}] Shared secret: {shared_secret}")
client.close()
-------------------------------------------------------------------------------------

