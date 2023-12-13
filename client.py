import socket
import threading
from rsa import generate_keypair, encrypt, decrypt

def start_client():
    server_address = ('localhost', 12345)

    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
    client_socket.connect(server_address)
    print("Client connected on port 12345")
    # Generate RSA key pair for the client
    client_public_key, client_private_key = generate_keypair(2048)

    # Send the client's public key to the server
    send_key(client_socket, client_public_key)

    # Receive the server's public key
    server_public_key = receive_key(client_socket)

    # Start a thread to handle messages from the server
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, client_private_key))
    receive_thread.start()

    # Code for sending messages to the server
    while True:
        message_to_send = input("You: ")

        # Convert the message to an integer
        message_int = int.from_bytes(message_to_send.encode(), byteorder='big')

        encrypted_message = encrypt(message_int, server_public_key)

        # Convert the encrypted message to bytes before getting its length
        encrypted_message_bytes = encrypted_message.to_bytes((encrypted_message.bit_length() + 7) // 8, byteorder='big')

        # Send the length of the encrypted message
        client_socket.sendall(len(encrypted_message_bytes).to_bytes(4, byteorder='big'))
        # Send the encrypted message itself
        client_socket.sendall(encrypted_message_bytes)

def receive_messages(socket, private_key):
    while True:
        # Receive acknowledgment from the server
        ack_message = socket.recv(2048)
        if not ack_message:
            break
        
        ack_message = ack_message.decode(errors='ignore')
        print(f"Server: {ack_message}")

        # Receive the length of the encrypted message
        message_length = int.from_bytes(socket.recv(4), byteorder='big')

        # Receive the encrypted message itself
        encrypted_message_bytes = socket.recv(message_length)
        if not encrypted_message_bytes:
            break

        # Convert the encrypted message bytes back to an integer
        encrypted_message = int.from_bytes(encrypted_message_bytes, byteorder='big')

        # Decrypt the message
        decrypted_message = decrypt(encrypted_message, private_key)

        print(f"Received message: {decrypted_message}")

def send_key(socket, key):
    # Send the length of the modulus
    modulus_length = len(str(key[0]).encode())
    socket.sendall(modulus_length.to_bytes(4, byteorder='big'))

    # Send the modulus itself
    socket.sendall(str(key[0]).encode())

    # Send the length of the public exponent
    exponent_length = len(str(key[1]).encode())
    socket.sendall(exponent_length.to_bytes(4, byteorder='big'))

    # Send the public exponent itself
    socket.sendall(str(key[1]).encode())

def receive_key(socket):
    # Receive the length of the modulus
    modulus_length = int.from_bytes(socket.recv(4), byteorder='big')

    # Receive the modulus itself
    modulus = socket.recv(modulus_length)
    n = int(modulus.decode())

    # Receive the length of the public exponent
    exponent_length = int.from_bytes(socket.recv(4), byteorder='big')

    # Receive the public exponent itself
    exponent = socket.recv(exponent_length)
    e = int(exponent.decode())

    return n, e

if __name__ == "__main__":
    start_client()
