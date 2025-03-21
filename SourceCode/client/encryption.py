from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

def encrypt_file(password, input_file, output_file):
    aes_key = get_random_bytes(32)  
    hmac_key = get_random_bytes(32) 

    salt = get_random_bytes(16)
    password_hash = PBKDF2(password, salt, dkLen=32, count=100000)

    # Encrypt the file
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv

    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Compute HMAC
    hmac = HMAC.new(hmac_key, salt + iv + password_hash + ciphertext, SHA256).digest()

    # Store salt, IV, password hash, HMAC, and ciphertext in the output file
    with open(output_file, "wb") as f:
        f.write(salt + iv + password_hash + hmac + ciphertext)

    print("File encrypted successfully!")

    return aes_key, hmac_key


def decrypt_file(password, input_file, output_file, aes_key, hmac_key):
    with open(input_file, "rb") as f:
        file_data = f.read()

    salt = file_data[:16]
    iv = file_data[16:32]
    stored_password_hash = file_data[32:64]
    stored_hmac = file_data[64:96]
    ciphertext = file_data[96:]

    # Verify the password
    computed_hash = PBKDF2(password, salt, dkLen=32, count=100000)

    if stored_password_hash != computed_hash:
        raise ValueError("Incorrect password. Decryption denied!")

    # Verify HMAC
    computed_hmac = HMAC.new(hmac_key, salt + iv + stored_password_hash + ciphertext, SHA256).digest()
    
    if stored_hmac != computed_hmac:
        raise ValueError("Authentication failed! Data has been tampered with.")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(plaintext.decode("utf-8"))

    print(f"Decryption successful! File saved as: {output_file}")



aes_key, hmac_key = encrypt_file(b"correctpassword", "example.txt", "encrypted.bin")

try:
    decrypt_file(b"correctpassword", "encrypted.bin", "decrypted.txt", aes_key, hmac_key)
except ValueError as e:
    print(e)