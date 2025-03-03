from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os
import getpass

# Constants
MAGIC_HEADER = b'ENCFILE'  # Identifier to mark files processed by this tool
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000
BLOCK_SIZE = 128

def generate_key(password, salt):
    """Generates a key from the given password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    """Encrypts a single file in-place, skipping if it's already encrypted."""
    with open(file_path, 'rb') as f:
        data = f.read()

    # Check if file is already encrypted
    if data.startswith(MAGIC_HEADER):
        print(f"File '{file_path}' is already encrypted. Skipping encryption.")
        return

    salt = os.urandom(SALT_SIZE)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Overwrite the file with a header, salt, iv, and encrypted data.
    with open(file_path, 'wb') as f:
        f.write(MAGIC_HEADER + salt + iv + encrypted_data)
    print(f"Encrypted file: {file_path}")

def decrypt_file(file_path, password):
    """
    Decrypts a single file in-place.
    If the file does not have the magic header (i.e. is already decrypted or never encrypted by this tool),
    it will be skipped. This check prevents double decryption.
    """
    with open(file_path, 'rb') as f:
        header = f.read(len(MAGIC_HEADER))
        if header != MAGIC_HEADER:
            print(f"File '{file_path}' does not appear to be encrypted (or may have already been decrypted). Skipping decryption.")
            return
        salt = f.read(SALT_SIZE)
        iv = f.read(16)
        encrypted_data = f.read()

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Overwrite the file with the decrypted data.
    with open(file_path, 'wb') as f:
        f.write(unpadded_data)
    print(f"Decrypted file: {file_path}")

def process_directory(directory_path, password, mode):
    """
    Recursively processes all files in a directory.
    mode: 'e' for encrypt, 'd' for decrypt.
    """
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if mode == 'e':
                    encrypt_file(file_path, password)
                else:
                    decrypt_file(file_path, password)
            except Exception as e:
                print(f"Error processing '{file_path}': {e}")

def process_path(path, password, mode):
    """
    If the path is a file, process it directly.
    If it's a directory, process all files recursively.
    """
    if os.path.isfile(path):
        try:
            if mode == 'e':
                encrypt_file(path, password)
            else:
                decrypt_file(path, password)
        except Exception as e:
            print(f"Error processing '{path}': {e}")
    elif os.path.isdir(path):
        process_directory(path, password, mode)
    else:
        print(f"Path '{path}' is neither a file nor a directory.")

def main():
    choice = input("Would you like to (E)ncrypt or (D)ecrypt? ").lower()
    if choice not in ['e', 'd']:
        print("Invalid choice. Please select 'E' for encrypt or 'D' for decrypt.")
        return

    path = input("Enter the path to the file or directory: ")
    if not os.path.exists(path):
        print("The specified path does not exist.")
        return

    password = getpass.getpass("Enter the password: ")
    process_path(path, password, choice)

if __name__ == "__main__":
    main()
