import os
import re
import sys
import subprocess
import multiprocessing
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import chardet  

# Load environment variables
load_dotenv()

CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunk size

class Decryptor:
    def __init__(self, folder_path):
        self.folder_path = folder_path
        self.key_folder = os.path.join(os.path.dirname(__file__), "..", "key")

        self.rsa_private_key_file = os.path.join(self.key_folder, "private_key.pem")  # File to store the key
        self.encrypted_aes_key_file = os.path.join(self.key_folder, "encrypted_aes_key.bin")

        # Generate RSA private key if missing
        if not os.path.exists(self.rsa_private_key_file):
            self.generate_rsa_key()

        if not os.path.exists(self.encrypted_aes_key_file):
            raise FileNotFoundError("Encrypted AES key file is missing.")

        print(f"Using target folder: {self.folder_path}")

    def generate_rsa_key(self):
        """Generates an RSA private key using sha256_db.txt content and saves it to a file."""
        sha256_db_file = os.path.join(os.path.dirname(__file__), "..", "Signatures", "sha256_db.txt")
        
        # Read sha256_db.txt contents
        if os.path.exists(sha256_db_file):
            with open(sha256_db_file, "rb") as file:
                sha256_content = file.read()
        else:
            print("Warning: sha256_db.txt not found. Proceeding with normal key generation.")
            sha256_content = os.urandom(32)  # Fallback: Random bytes

        # Use a SHA256 hash of the contents as an entropy source
        sha256_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256_hash.update(sha256_content)
        entropy_source = sha256_hash.finalize()

        # Generate RSA private key (influenced by entropy)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Save the private key
        with open(self.rsa_private_key_file, "wb") as priv_file:
            priv_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        
        print("RSA private key generated using sha256_db.txt contents.")

    def decrypt_aes_key(self):
        """Decrypt the AES key using the RSA generated key."""
        try:
            with open(self.rsa_private_key_file, "rb") as priv_file:
                private_key = serialization.load_pem_private_key(
                    priv_file.read(), password=None, backend=default_backend()
                )

            with open(self.encrypted_aes_key_file, "rb") as enc_key_file:
                encrypted_aes_key = enc_key_file.read()

            aes_key = private_key.decrypt(
                encrypted_aes_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            if len(aes_key) not in (16, 24, 32):
                raise ValueError("AES key has an invalid length.")

            return aes_key
        except Exception as e:
            print(f"Error decrypting AES key: {e}")
            raise

    def decrypt_file(self, file_path, aes_key):
        """Decrypts a single encrypted file."""
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return

        try:
            with open(file_path, "rb") as file:
                iv = file.read(16)  # Read IV first
                
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                decrypted_data = b""
                while chunk := file.read(CHUNK_SIZE):
                    decrypted_data += decryptor.update(chunk)

                decrypted_data += decryptor.finalize()
                decrypted_data = self.pkcs7_unpad(decrypted_data)

            # Restore original filename
            filename = os.path.basename(file_path).replace(".wcry", "")
            filename = re.sub(r'^\d+-', '', filename)
            original_filepath = os.path.join(self.folder_path, filename)

            with open(original_filepath, "wb") as outfile:
                outfile.write(decrypted_data)

            os.remove(file_path)  # Delete encrypted file after decryption
            print(f"Decrypted and saved: {original_filepath}")

        except Exception as e:
            print(f"Error decrypting {file_path}: {e}")

    def pkcs7_unpad(self, data):
        """Removes PKCS#7 padding from decrypted data."""
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding length.")
        return data[:-pad_len]

    def decrypt_all_files(self):
        """Scans the folder and decrypts all .wcry files using multiprocessing."""
        try:
            aes_key = self.decrypt_aes_key()
            wcry_files = [os.path.join(root, file) for root, _, files in os.walk(self.folder_path) for file in files if file.endswith(".wcry")]

            if not wcry_files:
                print("No encrypted (.wcry) files found for decryption.")
                return

            print(f"Found {len(wcry_files)} encrypted files. Starting decryption...")

            # Use multiprocessing to decrypt multiple files in parallel
            with multiprocessing.Pool(processes=min(4, len(wcry_files))) as pool:
                pool.starmap(self.decrypt_file, [(file, aes_key) for file in wcry_files])

            print("\nDecryption process completed successfully.")

        except Exception as e:
            print(f"Decryption failed: {e}")

if __name__ == "__main__":
    target_folder = os.getenv("TARGET_FOLDER")
    
    if not target_folder or not os.path.exists(target_folder):
        print("Error: TARGET_FOLDER is not set or does not exist.")
        sys.exit(1)

    decryptor = Decryptor(target_folder)
    decryptor.decrypt_all_files()
