from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from os import urandom
import base64

# Function to generate a random key for AES encryption
def generate_random_key():
    return urandom(32)  # Generate a secure random 256-bit key

# Static key and IV (insecure)
STATIC_KEY = b'\x01' * 32  # 256-bit key: Not recommended, always the same
STATIC_IV = b'\x02' * 16   # 128-bit IV: Not recommended, always the same

# Function to generate a secure random IV
def generate_random_iv():
    return urandom(16)  # Secure IV: Randomly generated

# Function to encrypt data using AES in CBC mode
def encrypt_data_aes_cbc(key, plaintext, iv):
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad plaintext to be a multiple of 16 bytes (block size)
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + (chr(padding_length) * padding_length).encode()

        # Encrypt the data
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

# Function to hash ciphertext using SHA-1
def hash_ciphertext_with_sha1(ciphertext):
    try:
        # Create a SHA-1 hash object
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(ciphertext.encode('utf-8'))
        # Return the hexadecimal representation of the hash
        return digest.finalize().hex()
    except Exception as e:
        print(f"Error during hashing: {e}")
        return None

# Function to prompt user for plaintext with error handling
def get_user_input():
    try:
        user_plaintext = input("Enter the plaintext message you want to encrypt: ")
        if not user_plaintext.strip():
            raise ValueError("Plaintext cannot be empty. Please enter a valid message.")
        return user_plaintext.encode('utf-8')
    except ValueError as ve:
        print(ve)
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

# Function to prompt user to rerun or exit
def prompt_rerun():
    try:
        user_input = input("\nDo you want to run the encryption again? (y/n): ").strip().lower()
        if user_input not in ['y', 'n']:
            raise ValueError("Invalid input. Please enter 'y' for yes or 'n' for no.")
        return user_input == 'y'
    except ValueError as ve:
        print(ve)
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

# Function to demonstrate encryption with static vs random key and IV
def demonstrate_static_vs_random_key_iv():
    while True:
        plaintext = get_user_input()
        if plaintext is None:
            return  # Exit if there's an error in user input

        try:
            # Encrypt using a static key and static IV
            static_key_encrypted = encrypt_data_aes_cbc(STATIC_KEY, plaintext, STATIC_IV)
            if static_key_encrypted:
                static_hash = hash_ciphertext_with_sha1(static_key_encrypted)
                print(f"\nStatic Key: {STATIC_KEY.hex()}")
                print(f"Static IV: {STATIC_IV.hex()}")
                print(f"Encryption with Static Key & Static IV: {static_key_encrypted}")
                print(f"SHA-1 Hash of Static Encrypted Ciphertext: {static_hash}")

            # Encrypt using a random key and random IV
            random_key = generate_random_key()
            random_iv = generate_random_iv()
            random_key_encrypted = encrypt_data_aes_cbc(random_key, plaintext, random_iv)
            if random_key_encrypted:
                random_hash = hash_ciphertext_with_sha1(random_key_encrypted)
                print(f"\nRandom Key: {random_key.hex()}")
                print(f"Random IV: {random_iv.hex()}")
                print(f"Encryption with Random Key & Random IV: {random_key_encrypted}")
                print(f"SHA-1 Hash of Random Encrypted Ciphertext: {random_hash}")

        except Exception as e:
            print(f"Unexpected error during demonstration: {e}")

        # Prompt user to rerun or exit
        if not prompt_rerun():
            break

# Run the demonstration
demonstrate_static_vs_random_key_iv()
