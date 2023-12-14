#cs 454
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64


def generate_aes_key():
    return get_random_bytes(16) 


def prepare_message(message):
   #this is the section that prepares the message, he mentioned that we didn't have to do padding but I feel like it was harder without it so I did it
    return pad(message.encode('utf-8'), AES.block_size)

#these functions are the encryption and decyption functions for each mode, they're all similar since they do practically the same thing. I didn't implement any modes myself I just used to library for all of them 
def encrypt_ecb(message, key, iv): #fake iv so that my loop works later it doesnt need iv
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(message)
    return ciphertext
def decrypt_ecb(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)
def encrypt_cbc(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(message)
    return ciphertext
def decrypt_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)
def encrypt_cfb(message, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(message)
    return ciphertext
def decrypt_cfb(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)
def encrypt_ofb(message, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(message)
    return ciphertext
def decrypt_ofb(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)
def encrypt_ctr(message, key, nonce):
    ctr = Counter.new(nbits=64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(message)
    return ciphertext
def decrypt_ctr(ciphertext, key, nonce):
    ctr = Counter.new(nbits=64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)


key = generate_aes_key()
iv = get_random_bytes(AES.block_size)  
nonce = get_random_bytes(8)
message = "Hello, this is a sample message for encryption and decryption using AES modes."

encrypted_ecb = encrypt_ecb(prepare_message(message), key, iv)
decrypted_ecb = decrypt_ecb(encrypted_ecb, key, iv)
encrypted_cbc = encrypt_cbc(prepare_message(message), key, iv)
decrypted_cbc = decrypt_cbc(encrypted_cbc, key, iv)
encrypted_cfb = encrypt_cfb(prepare_message(message), key, iv)
decrypted_cfb = decrypt_cfb(encrypted_cfb, key, iv)
encrypted_ofb = encrypt_ofb(prepare_message(message), key, iv)
decrypted_ofb = decrypt_ofb(encrypted_ofb, key, iv)
encrypted_ctr = encrypt_ctr(prepare_message(message), key, nonce)
decrypted_ctr = decrypt_ctr(encrypted_ctr, key, nonce)

#results
print("ECB Mode: \n Original:", message)
print("Encrypted:", base64.b64encode(encrypted_ecb).decode('utf-8'))
print("Decrypted:", decrypted_ecb.decode('utf-8'))
print()

print("CBC Mode: \n Original:", message)
print("Encrypted:", base64.b64encode(encrypted_cbc).decode('utf-8'))
print("Decrypted:", decrypted_cbc.decode('utf-8'))
print()

print("CFB Mode: \n Original:", message)
print("Encrypted:", base64.b64encode(encrypted_cfb).decode('utf-8'))
print("Decrypted:", decrypted_cfb.decode('utf-8'))
print()

print("OFB Mode: \n Original:", message)
print("Encrypted:", base64.b64encode(encrypted_ofb).decode('utf-8'))
print("Decrypted:", decrypted_ofb.decode('utf-8'))
print()

print("CTR Mode: \n Original:", message)
print("Encrypted:", base64.b64encode(encrypted_ctr).decode('utf-8'))
print("Decrypted:", decrypted_ctr.decode('utf-8'))
