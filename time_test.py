from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64
import timeit
from aes_functions import generate_aes_key, prepare_message, encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc, encrypt_cfb, decrypt_cfb, encrypt_ofb, decrypt_ofb, encrypt_ctr, decrypt_ctr

def measure_time(func, *args):
    return timeit.timeit(lambda: func(*args), number=100) / 100

iv = get_random_bytes(AES.block_size)
message = "Hello, this is a sample message for encryption and decryption using AES modes."
nonce = get_random_bytes(8)
key = generate_aes_key()

encrypted_ecb, encryption_time_ecb = measure_time(encrypt_ecb, prepare_message(message), key, iv)
decrypted_ecb, decryption_time_ecb = measure_time(decrypt_ecb, encrypted_ecb, key, iv)
encrypted_cbc, encryption_time_cbc = measure_time(encrypt_cbc, prepare_message(message), key, iv)
decrypted_cbc, decryption_time_cbc = measure_time(decrypt_cbc, encrypted_cbc, key, iv)
encrypted_cfb, encryption_time_cfb = measure_time(encrypt_cfb, prepare_message(message), key, iv)
decrypted_cfb, decryption_time_cfb = measure_time(decrypt_cfb, encrypted_cfb, key, iv)
encrypted_ofb, encryption_time_ofb = measure_time(encrypt_ofb, prepare_message(message), key, iv)
decrypted_ofb, decryption_time_ofb = measure_time(decrypt_ofb, encrypted_ofb, key, iv)
encrypted_ctr, encryption_time_ctr = measure_time(encrypt_ctr, prepare_message(message), key, nonce)
decrypted_ctr, decryption_time_ctr = measure_time(decrypt_ctr, encrypted_ctr, key, nonce)


print("ECB Mode: \nOriginal: ", message)
print("Encrypted:", base64.b64encode(encrypted_ecb).decode('utf-8'))
print("Decrypted:", decrypted_ecb.decode('utf-8'))
print(f"Encryption Time: {encryption_time_ecb} seconds")
print(f"Decryption Time: {decryption_time_ecb} seconds\n")


print("CBC Mode: \nOriginal: ", message)
print("Encrypted:", base64.b64encode(encrypted_cbc).decode('utf-8'))
print("Decrypted:", decrypted_cbc.decode('utf-8'))
print(f"Encryption Time: {encryption_time_cbc} seconds")
print(f"Decryption Time: {decryption_time_cbc} seconds\n")

print("CFB Mode: \nOriginal: ", message)
print("Encrypted:", base64.b64encode(encrypted_cfb).decode('utf-8'))
print("Decrypted:", decrypted_cfb.decode('utf-8'))
print(f"Encryption Time: {encryption_time_cfb} seconds")
print(f"Decryption Time: {decryption_time_cfb} seconds\n")

print("OFB Mode: \nOriginal: ", message)
print("Encrypted:", base64.b64encode(encrypted_ofb).decode('utf-8'))
print("Decrypted:", decrypted_ofb.decode('utf-8'))
print(f"Encryption Time: {encryption_time_ofb} seconds")
print(f"Decryption Time: {decryption_time_ofb} seconds\nbits")

print("CTR Mode: \nOriginal: ", message)
print("Encrypted:", base64.b64encode(encrypted_ctr).decode('utf-8'))
print("Decrypted:", decrypted_ctr.decode('utf-8'))
print(f"Encryption Time: {encryption_time_ctr} seconds")
print(f"Decryption Time: {decryption_time_ctr} seconds\n")



