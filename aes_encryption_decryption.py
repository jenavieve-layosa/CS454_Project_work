# CS 454 
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from Crypto.Util import Counter
import base64
import random
# grab the needed functions from our other file 
from aes_functions import generate_aes_key, prepare_message, encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc, encrypt_cfb, decrypt_cfb, encrypt_ofb, decrypt_ofb, encrypt_ctr, decrypt_ctr

def generate_iv(iv_length):
    return get_random_bytes(iv_length)

def introduce_errors(ciphertext, error_rate):
    num_errors = int(len(ciphertext) * error_rate) 
    error_indices = random.sample(range(len(ciphertext)), num_errors)
    # flips the bits at the specified indicies and uses the error rate to see how many need to be flipped
    for index in error_indices:
        byte_value = ciphertext[index]
        flipped_byte = bytes([byte_value ^ 1])
        ciphertext = ciphertext[:index] + flipped_byte + ciphertext[index + 1:]

def error_propagation_analysis(mode_name, encrypt_function, decrypt_function, key, iv_length, nonce, message, error_rate):
    print(f"\n{mode_name} Mode with Error Propagation Analysis: ")

    try:

        encrypted_message = encrypt_function(prepare_message(message), key, generate_iv(iv_length))

        introduce_errors(encrypted_message, error_rate)

        #count error bits??

        try:
            decrypted_message = decrypt_function(encrypted_message, key, generate_iv(iv_length))

            print("Original:", message)
            print("Encrypted (with errors):", base64.b64encode(encrypted_message).decode('utf-8'))
            print("Decrypted:", decrypted_message.decode('utf-8'))
            print()
        #need to have error handling so that it doesn't stop when it breaks because we want to see the errors 
        except Exception as decrypt:
            print(f"Decryption Error: {decrypt}")
            print()
    

    except Exception as encrypt:
        print(f"Encryption Error: {encrypt}")
        print()


key = generate_aes_key()
nonce = get_random_bytes(8)
message = "Hello, this is a sample message for encryption and decryption using AES modes."
error_rate = 0.05 
error_propagation_analysis("ECB", encrypt_ecb, decrypt_ecb, key, 0, nonce, message, error_rate)
error_propagation_analysis("CBC", encrypt_cbc, decrypt_cbc, key, AES.block_size, nonce, message, error_rate)
error_propagation_analysis("CFB", encrypt_cfb, decrypt_cfb, key, AES.block_size, nonce, message, error_rate)
error_propagation_analysis("OFB", encrypt_ofb, decrypt_ofb, key, AES.block_size, nonce, message, error_rate)
error_propagation_analysis("CTR", encrypt_ctr, decrypt_ctr, key, 0, nonce, message, error_rate)
