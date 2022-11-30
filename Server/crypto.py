from Crypto.Cipher import AES 
from Crypto.PublicKey import RSA 
from Crypto import Random 
from base64 import b64encode 
from base64 import b64decode 
import json
import hashlib

def generate_aes_key():
    return Random.get_random_bytes(AES.key_size[0])


def pad(s):
    return s + ((16-len(s) % 16)* '{')

def RSA_encrypt(plaintext, cipher):
    return cipher.encrypt(pad(plaintext))

def decrypt(ciphertext, cipher):
    dec = cipher.decrypt(ciphertext).decode('utf-8')
    l = dec.count('{')
    return dec[:len(dec)-1]    

def encrypt_str(src_str, AES_KEY):
    byte_str = json.dumps(src_str).encode()
    NONCE = Random.get_random_bytes(AES.block_size-1)
    cipher = AES.new(AES_KEY, AES.MODE_OCB, NONCE)
    ciphertxt, MAC = cipher.encrypt_and_digest(byte_str)
    return b64encode(ciphertxt).decode(), NONCE.decode('latin-1'), MAC.decode('latin-1')
                                                                              
def decrypt_str(en_str, NONCE, MAC, AES_KEY): 
    ciphertxt = b64decode(en_str)
    cipher = AES.new(AES_KEY, AES.MODE_OCB, NONCE.encode('latin-1'))
    src_str = cipher.decrypt_and_verify(ciphertxt, MAC.encode('latin-1')).decode() 
    src_dict = json.loads(json.loads(src_str))
    return src_dict
