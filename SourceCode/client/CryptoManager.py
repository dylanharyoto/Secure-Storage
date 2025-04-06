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
    def encrypt_with_aes(password):
        password = password.encode('utf-8')
        aes_key = get_random_bytes(32)
        salt = hmac.new(password, password, hashlib.sha512).digest()[:16]
        derived_key = PBKDF2(password, salt, dkLen=32, count=100000)
        combined_key = b"true" + aes_key
        cipher = AES.new(derived_key, AES.MODE_CBC)
        encrypted_aes_key = cipher.encrypt(pad(combined_key, AES.block_size)) + cipher.iv
        return encrypted_aes_key, derived_key
    
    @staticmethod
    def generate_rsa_key_pair():
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    @staticmethod
    def encrypt_file_with_aes(password, encrypted_key_data, input_file_path):
        password = password.encode('utf-8')
        key_iv = encrypted_key_data[48:]
        encrypted_aes_key = encrypted_key_data[:48]
        salt = hmac.new(password, password, hashlib.sha512).digest()[:16]
        derived_key = PBKDF2(password, salt, dkLen=32, count=100000)
        key_cipher = AES.new(derived_key, AES.MODE_CBC, key_iv)
        combined_key = unpad(key_cipher.decrypt(encrypted_aes_key), AES.block_size)
        aes_key = combined_key[4:]
        cipher = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher.iv
        with open(input_file_path, "rb") as file:
            plaintext = file.read()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        print("File encrypted successfully!")
        return iv + ciphertext
    
    @staticmethod
    def decrypt_file_with_aes(password, encrypted_key_data, file_data, output_file_path):
        password = password.encode('utf-8')
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
        with open(output_file_path, "w", encoding="utf-8") as file:
            file.write(plaintext.decode("utf-8"))
        print(f"Decryption successful! File saved as: {output_file_path}")

    @staticmethod
    def verify_recovery_key(recovery_key, encrypted_key_data):
        key_iv = encrypted_key_data[48:]
        encrypted_aes_key = encrypted_key_data[:48]
        cipher = AES.new(recovery_key, AES.MODE_CBC, key_iv)
        combined_key = unpad(cipher.decrypt(encrypted_aes_key), AES.block_size)
        if combined_key[:4] == b"true":
            return True
        else:
            print("Invalid password")
            return False
        
    @staticmethod
    def encrypt_file_for_sharing(public_key, plaintext):
        aes_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        rsa_key = RSA.import_key(public_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        return len(encrypted_aes_key).to_bytes(2, "big") + encrypted_aes_key + iv + ciphertext
    
    @staticmethod
    def decrypt_shared_file(private_key, encrypted_data, output_file_path):
        key_length = int.from_bytes(encrypted_data[:2], "big")
        break_point1 = key_length + 2
        encrypted_aes_key = encrypted_data[2:break_point1]
        break_point2 = break_point1 + 16
        iv = encrypted_data[break_point1:break_point2]
        ciphertext = encrypted_data[break_point2:]
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
        with open(output_file_path, "wb") as file:
            file.write(plaintext)
        print(f"File decrypted and saved as {output_file_path}")
    
    @staticmethod
    def hash_password(password):
        password = password.encode('utf-8')
        initial_hash = hmac.new(password, password, hashlib.sha512).digest()
        salt = hmac.new(initial_hash, initial_hash, hashlib.sha512).digest()[:16]
        base64_salt = base64.b64encode(salt).decode('utf-8')
        base64_salt = base64_salt.replace('+', '.').replace('=', '')
        bcrypt_salt = f"$2b${12}${base64_salt}".encode('utf-8')
        password_hash = bcrypt.hashpw(password, bcrypt_salt)
        return password_hash