import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(num, accuracy=5):
    if num == 2 or num == 3:
        return True
    if num < 2 or num % 2 == 0:
        return False

    r, d = 0, num - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(accuracy):
        a = random.randint(2, num - 2)
        x = pow(a, d, num)
        if x == 1 or x == num - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False
    return True

def generate_keypair(bits):
    p = random_prime(bits)
    q = random_prime(bits)

    # Calculate n and totient
    n = p * q
    totient = (p - 1) * (q - 1)

    # Choose public exponent e
    e = 65537  # Commonly used value for e

    # Calculate private exponent d
    d = mod_inverse(e, totient)

    return ((n, e), (n, d))

def encrypt(message, public_key):
    n, e = public_key
    cipher_text = pow(message, e, n)
    return cipher_text

def decrypt(encrypted_message, private_key):
    decrypted_message = pow(encrypted_message, private_key[1], private_key[0])
    return decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, 'big')



def random_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

# # Example usage:
# message = 42  # Change this to your actual message
# public_key, private_key = generate_keypair(2048)

# encrypted_message = encrypt(message, public_key)
# decrypted_message = decrypt(encrypted_message, private_key)

# print(f"Original Message: {message}")
# print(f"Encrypted Message: {encrypted_message}")
# print(f"Decrypted Message: {decrypted_message}")


# import unittest

# class TestRSAEncryptionDecryption(unittest.TestCase):
#     def test_encryption_decryption(self):
#         # Generate key pair
#         key_pair = generate_keypair(2048)
#         public_key, private_key = key_pair

#         # Test message
#         original_message = "Hello, RSA Encryption and Decryption!"

#         # Encrypt the message
#         encrypted_message = encrypt(original_message, public_key)

#         # Decrypt the message
#         decrypted_message = decrypt(encrypted_message, private_key)

#         # Assert that the decrypted message matches the original message
#         self.assertEqual(original_message, decrypted_message)

# if __name__ == '__main__':
#     unittest.main()
