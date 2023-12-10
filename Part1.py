# Import necessary libraries
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64

# Function to generate a random AES key
def generate_aes_key():
    return get_random_bytes(16)  # 16 bytes for AES-128

# Function to prepare a message (plaintext)
def prepare_message(message):
    # Convert the message to bytes and pad it
    return pad(message.encode('utf-8'), AES.block_size)

# Function to encrypt a message using AES in ECB mode
def encrypt_ecb(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(message)
    return ciphertext

# Function to decrypt a message using AES in ECB mode
def decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

# Function to encrypt a message using AES in CBC mode
def encrypt_cbc(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(message)
    return ciphertext

# Function to decrypt a message using AES in CBC mode
def decrypt_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

# Function to encrypt a message using AES in CFB mode
def encrypt_cfb(message, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(message)
    return ciphertext

# Function to decrypt a message using AES in CFB mode
def decrypt_cfb(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

# Function to encrypt a message using AES in OFB mode
def encrypt_ofb(message, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(message)
    return ciphertext

# Function to decrypt a message using AES in OFB mode
def decrypt_ofb(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

# Function to encrypt a message using AES in CTR mode
def encrypt_ctr(message, key, nonce):
    ctr = Counter.new(nbits=64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(message)
    return ciphertext

# Function to decrypt a message using AES in CTR mode
def decrypt_ctr(ciphertext, key, nonce):
    ctr = Counter.new(nbits=64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

# Example usage
key = generate_aes_key()
iv = get_random_bytes(AES.block_size)  # Initialization Vector

message = "Hello, this is a sample message for encryption and decryption using AES modes."

# ECB Mode
encrypted_ecb = encrypt_ecb(prepare_message(message), key)
decrypted_ecb = decrypt_ecb(encrypted_ecb, key)

# CBC Mode
encrypted_cbc = encrypt_cbc(prepare_message(message), key, iv)
decrypted_cbc = decrypt_cbc(encrypted_cbc, key, iv)

# CFB Mode
encrypted_cfb = encrypt_cfb(prepare_message(message), key, iv)
decrypted_cfb = decrypt_cfb(encrypted_cfb, key, iv)

# OFB Mode
encrypted_ofb = encrypt_ofb(prepare_message(message), key, iv)
decrypted_ofb = decrypt_ofb(encrypted_ofb, key, iv)

# CTR Mode
nonce = get_random_bytes(8)
encrypted_ctr = encrypt_ctr(prepare_message(message), key, nonce)
decrypted_ctr = decrypt_ctr(encrypted_ctr, key, nonce)

# Print results
print("ECB Mode:")
print("Original:", message)
print("Encrypted:", base64.b64encode(encrypted_ecb).decode('utf-8'))
print("Decrypted:", decrypted_ecb.decode('utf-8'))
print()

print("CBC Mode:")
print("Original:", message)
print("Encrypted:", base64.b64encode(encrypted_cbc).decode('utf-8'))
print("Decrypted:", decrypted_cbc.decode('utf-8'))
print()

print("CFB Mode:")
print("Original:", message)
print("Encrypted:", base64.b64encode(encrypted_cfb).decode('utf-8'))
print("Decrypted:", decrypted_cfb.decode('utf-8'))
print()

print("OFB Mode:")
print("Original:", message)
print("Encrypted:", base64.b64encode(encrypted_ofb).decode('utf-8'))
print("Decrypted:", decrypted_ofb.decode('utf-8'))
print()

print("CTR Mode:")
print("Original:", message)
print("Encrypted:", base64.b64encode(encrypted_ctr).decode('utf-8'))
print("Decrypted:", decrypted_ctr.decode('utf-8'))
