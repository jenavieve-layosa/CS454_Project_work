#cs 454
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time
import base64

def generate_key_pair():
    key= RSA.generate(2048) 
    privatekey= key.export_key()
    publickey= key.publickey().export_key()
    return privatekey, publickey
def encrypt(message, publickey):
    key =RSA.import_key(publickey)
    cipher= PKCS1_OAEP.new(key)
    ciphertext= cipher.encrypt(message)
    return ciphertext
def decrypt(ciphertext, privatekey):
    key = RSA.import_key(privatekey)
    cipher= PKCS1_OAEP.new(key)
    plaintext= cipher.decrypt(ciphertext)
    return plaintext
def time_operations(message, publickey, privatekey, trials=5):
    print(f"Original Message: {message.decode('utf-8')}")

    for i in range(trials):
        print(f"\nIteration: {i + 1}")
        start=time.time()
        ciphertext=encrypt(message, publickey)
        encryption_time=time.time()-start
        print("Encrypted Message: ", base64.b64encode(ciphertext).decode('utf-8'))
        start=time.time()
        decrypted_message=decrypt(ciphertext, privatekey)
        decryption_time=time.time()-start
        print("Decrypted Message: ", decrypted_message.decode('utf-8'))
        print("Encryption Time: ", encryption_time, " seconds \n Decryption Time: ", decryption_time, " seconds ")


message=b" Hello!! this is a sample message for RSA encryption and decryption. "
privatekey, publickey=generate_key_pair()

time_operations(message, publickey, privatekey)
