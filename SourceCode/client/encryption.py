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

# AES and RSA generation
def AES_encrypt(password):
    # Generate random aeskey
    aes_key = get_random_bytes(32) 

    # Derive salt from password and generate password hash 
    salt = hmac.new(password, password, hashlib.sha512).digest()[:16]
    password_hash = PBKDF2(password, salt, dkLen=32, count=100000)

    # Encrypt the key using password hash
    combined_key = b"true" + aes_key # Add validation tag
    cipher_key = AES.new(password_hash, AES.MODE_CBC)
    key_iv = cipher_key.iv
    encrypted_aes_key = cipher_key.encrypt(pad(combined_key, AES.block_size))
    encrypted_combined_key = encrypted_aes_key + key_iv
    return encrypted_combined_key, password_hash
# Example Usage
#encrypted_combined_key, recover_key = AES_encrypt(b"correctpassword")

# Generate a random RSA key pair.
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key
# Example Usage
#private_key, public_key = generate_rsa_keys()

################################################################################################
# AES Encryption
def encrypt_file(password, encrypted_combined_key, input_file):
    key_iv = encrypted_combined_key[48:]
    encrypted_aes_key = encrypted_combined_key[:48]
    # Generate the password key and decrypt the aeskey
    salt = hmac.new(password, password, hashlib.sha512).digest()[:16]
    password_key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher_key = AES.new(password_key, AES.MODE_CBC, key_iv)
    combined_key = unpad(cipher_key.decrypt(encrypted_aes_key), AES.block_size)
    aes_key = combined_key[4:]

    # Encrypt the file using aeskey
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    with open(input_file, "rb") as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    print("File encrypted successfully!")
    return (iv + ciphertext)
# Example Usage
#encrypt_file(b"correctpassword", encrypted_combined_key, "example.txt")

# Decryption
def decrypt_file(password, encrypted_combined_key, file_data, output_file):

    # Read IV and ciphertext
    iv = file_data[:16]
    ciphertext = file_data[16:]

    # Extract information from the encrypted key
    key_iv = encrypted_combined_key[48:]
    encrypted_aes_key = encrypted_combined_key[:48]

    # Generate the password key and decrypt the aeskey
    salt = hmac.new(password, password, hashlib.sha512).digest()[:16]
    password_key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher_key = AES.new(password_key, AES.MODE_CBC, key_iv)

    # Check validation tag
    combined_key = unpad(cipher_key.decrypt(encrypted_aes_key), AES.block_size) 
    if combined_key[:4] == b"true":
        aes_key = combined_key[4:]
    else:
        print("Invalid password")
        return

    # Decrypt the cipher text using aeskey
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(plaintext.decode("utf-8"))

    print(f"Decryption successful! File saved as: {output_file}")
# Example Usage
#try:
#    decrypt_file(b"correctpassword", encrypted_combined_key, encrypted content, "decrypted.txt")
#except ValueError as e:
#    print(e)

# Varify the recover key
def recover_key_check(recover_key, encrypted_combined_key):
    key_iv = encrypted_combined_key[48:]
    encrypted_aes_key = encrypted_combined_key[:48]
    cipher_key = AES.new(recover_key, AES.MODE_CBC, key_iv)
    combined_key = unpad(cipher_key.decrypt(encrypted_aes_key), AES.block_size) 
    if combined_key[:4] == b"true":
        return True, recover_key
    else:
        print("Invalid password")
        return False
# Example Usage
#recover_key_check(recover_key, encrypted_combined_key)


################################################################################################
# RSA encryption
# Encrypts a file with AES and encrypts the AES key with receiver's public key
def encrypt_file_for_sharing(public_key, plaintext):  
    # Encrypt the file using AES-CBC
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Encrypt the AES key with receiver's public key
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return len(encrypted_aes_key).to_bytes(2, "big") + encrypted_aes_key + iv + ciphertext

# Example Usage
#encrypt_file_for_sharing(public_key, plaintext)

# Decrypts an AES-encrypted file using the receiver's private key
def decrypt_shared_file(private_key, data, output_file):
    key_length = int.from_bytes(data[:2], "big")
    break_point1 = key_length + 2
    encrypted_aes_key = data[2:break_point1]
    break_point2 = break_point1 + 16
    iv = data[break_point1:break_point2]
    ciphertext = data[break_point2:]

    # Decrypt the AES key with private key
    secret_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(secret_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Decrypt the file content
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    # Save the decrypted file
    with open(output_file, "wb") as f:
        f.write(plaintext)

    print(f"File decrypted and saved as {output_file}")
# Example Usage
#decrypt_shared_file(private_key, encrypted data, "decrypted.txt")

def password_hashA(password):
    # Derive salt from password and generate password hash 
    hash = hmac.new(password, password, hashlib.sha512).digest()
    salt = hmac.new(hash, hash, hashlib.sha512).digest()[:16]
    b64_salt = base64.b64encode(salt).decode('utf-8')
    b64_salt = b64_salt.replace('+', '.').replace('=', '')
    bcrypt_salt = f"$2b${12}${b64_salt}".encode('utf-8')
    password_hash = bcrypt.hashpw(password, bcrypt_salt)
    return password_hash

