from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import bcrypt
import base64

#.encode('utf-8')

class CryptoManager:
    @staticmethod
    def encrypt_with_aes(password, aes_key=get_random_bytes(32)):
        """
        Derive a recovery key from the given password and encrypt the AES key with it.

        Parameters:
        - password (str): User's password
        - aes_key (bytes): AES key to encrypt (default is a random 32-byte key)

        Returns:
        - encrypted_aes_key (bytes): AES key encrypted with recovery key
        - recovery_key (bytes): Derived key using PBKDF2 from password
        """
        password = password.encode("utf-8")
        salt = hmac.new(password, password, hashlib.sha512).digest()[:16]
        recovery_key = PBKDF2(password, salt, dkLen=32, count=100000)
        combined_key = b"true" + aes_key
        cipher = AES.new(recovery_key, AES.MODE_CBC)
        encrypted_aes_key = cipher.encrypt(pad(combined_key, AES.block_size)) + cipher.iv
        return encrypted_aes_key, recovery_key
    @staticmethod
    def generate_rsa_key_pair():
        """
        Generate an RSA key pair.

        Returns:
        - secret_key (bytes): private key
        - public_key (bytes): public key
        """
        key = RSA.generate(2048)
        secret_key = key.export_key()
        public_key = key.publickey().export_key()
        return secret_key, public_key
    @staticmethod
    def encrypt_file_with_aes(password, aes_key, encrypted_file_path):
        """
        Encrypt a file using AES, with AES key recovered from password.

        Parameters:
        - password (str): User's password
        - aes_key (bytes): Encrypted AES key + IV
        - encrypted_file_path (str): Path to the file to encrypt

        Returns:
        - encrypted_file_data (bytes): The IV + ciphertext of the encrypted file
        """
        password = password.encode("utf-8")
        key_iv = aes_key[48:]
        encrypted_aes_key = aes_key[:48]
        salt = hmac.new(password, password, hashlib.sha512).digest()[:16]
        derived_key = PBKDF2(password, salt, dkLen=32, count=100000)
        key_cipher = AES.new(derived_key, AES.MODE_CBC, key_iv)
        combined_key = unpad(key_cipher.decrypt(encrypted_aes_key), AES.block_size)
        aes_key = combined_key[4:]
        cipher = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher.iv
        with open(encrypted_file_path, "rb") as file:
            plaintext = file.read()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        encrypted_file_data = iv + ciphertext
        return encrypted_file_data
    
    @staticmethod
    def decrypt_file_with_aes(password, encrypted_key_data, file_data, output_file_path=None):
        """
        Decrypt a file encrypted with AES using a password-derived key.

        Parameters:
        - password (str): User's password
        - encrypted_key_data (bytes): Encrypted AES key + IV
        - file_data (bytes): Encrypted file data (IV + ciphertext)
        - output_file_path (str, optional): File path to write decrypted content (if given)

        Returns:
        - plaintext (bytes): Decrypted file data (if no output_file_path is provided)
        """
        password = password.encode("utf-8")
        iv = file_data[:16]
        ciphertext = file_data[16:]
        key_iv = encrypted_key_data[48:]
        encrypted_aes_key = encrypted_key_data[:48]
        salt = hmac.new(password, password, hashlib.sha512).digest()[:16]
        derived_key = PBKDF2(password, salt, dkLen=32, count=100000)
        key_cipher = AES.new(derived_key, AES.MODE_CBC, key_iv)
        combined_key = unpad(key_cipher.decrypt(encrypted_aes_key), AES.block_size)
        if combined_key[:4] == b"true":
            aes_key = combined_key[4:]
        else:
            print("Invalid password")
            return
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        if output_file_path is None:
            return plaintext
        with open(output_file_path, "wb") as file:
            file.write(plaintext)
        print(f"Decryption successful! File saved as: {output_file_path}")

    @staticmethod
    def verify_recovery_key(recovery_key, aes_key):
        """
        Verify a recovery key against an encrypted AES key.

        Parameters:
        - recovery_key (str): Base64-encoded recovery key
        - aes_key (bytes): Encrypted AES key + IV

        Returns:
        - bytes: Decrypted AES key if verification passes
        - bool: False if verification fails
        """
        # Decode the base64-encoded recovery key into raw bytes
        recovery_key_raw = base64.b64decode(recovery_key)
        key_iv = aes_key[48:]
        encrypted_aes_key = aes_key[:48]
        cipher = AES.new(recovery_key_raw, AES.MODE_CBC, key_iv)
        combined_key = unpad(cipher.decrypt(encrypted_aes_key), AES.block_size)
        if combined_key[:4] == b"true":
            return combined_key[4:]
        return False
        
    @staticmethod
    def encrypt_file_for_sharing(public_key, plaintext):
        """
        Encrypt a plaintext file for sharing using a recipient's RSA public key.

        Parameters:
        - public_key (bytes): the user's RSA public key
        - plaintext (bytes): File content to encrypt

        Returns:
        - bytes: Encrypted file data (key length + RSA-encrypted key + IV + ciphertext)
        """
        aes_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        rsa_key = RSA.import_key(public_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        return len(encrypted_aes_key).to_bytes(2, "big") + encrypted_aes_key + iv + ciphertext
    
    @staticmethod
    def decrypt_shared_file(secret_key, encrypted_data, output_file_path):
        """
        Decrypt a shared file using the recipient's RSA private key.

        Parameters:
        - secret_key (str): Base64-encoded RSA private key
        - encrypted_data (bytes): Full encrypted package (key + IV + ciphertext)
        - output_file_path (str): Path to write the decrypted file

        Returns:
        - None (writes decrypted file to output_file_path)
        """
        # Decode the base64-encoded secret key into raw bytes
        secret_key_raw = base64.b64decode(secret_key)
        key_length = int.from_bytes(encrypted_data[:2], "big")
        break_point1 = key_length + 2
        encrypted_aes_key = encrypted_data[2:break_point1]
        break_point2 = break_point1 + 16
        iv = encrypted_data[break_point1:break_point2]
        ciphertext = encrypted_data[break_point2:]
        rsa_key = RSA.import_key(secret_key_raw)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
        with open(output_file_path, "wb") as file:
            file.write(plaintext)
        print(f"File decrypted and saved as {output_file_path}")
    
    @staticmethod
    def hash_password(input_password):
        """Hash the password (HashA method) for log in authentication
        Parameters:
        - input_password (str): Plaintext password

        Returns:
        - bytes: bcrypt-hashed password
        """
        salt = bcrypt.gensalt()
        input_password = input_password.encode("utf-8")
        return bcrypt.hashpw(input_password, salt)

    
    @staticmethod
    def check_password(input_password, hashed_password):
        """Verify a password with the same HashA method for log in authentication
        Parameters:
        - input_password (str): Password to verify
        - hashed_password (str): bcrypt hashed password to compare against

        Returns:
        - bool: True if the password matches, False otherwise
        """
        input_password = input_password.encode("utf-8")
        hashed_password = hashed_password.encode("utf-8")
        return bcrypt.checkpw(input_password, hashed_password)