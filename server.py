import socket
import threading
from rsa import generate_keypair, encrypt, decrypt

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(5)

    print("Server listening on port 12345")

    # Generate RSA key pair for the server
    server_public_key, server_private_key = generate_keypair(2048)

    while True:
        client_socket, address = server.accept()
        print(f"Accepted connection from {address}")

        # Send the server's public key to the client
        send_key(client_socket, server_public_key)

        # Receive the client's public key
        client_public_key = receive_key(client_socket)

        # Start a thread to handle messages from the client
        handle_client_thread = threading.Thread(target=handle_client, args=(client_socket, client_public_key, server_private_key))
        handle_client_thread.start()


def handle_client(client_socket, client_public_key, server_private_key):
    while True:
        # Receive the length of the encrypted message
        message_length = int.from_bytes(client_socket.recv(4), byteorder='big')

        # Receive the encrypted message itself
        encrypted_message = client_socket.recv(message_length)
        if not encrypted_message:
            break

        # Decrypt the message
        decrypted_message = decrypt(int.from_bytes(encrypted_message, byteorder='big'), server_private_key)

        # Convert the decrypted message to a string
        decoded_message = decrypted_message.decode('utf-8')

        #print(f"Received encrypted message from client: {encrypted_message}")
        print(f"Decrypted message from client: {decoded_message}")

        # Send an acknowledgment to the client
        client_socket.send("Message received".encode())



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
    start_server()
