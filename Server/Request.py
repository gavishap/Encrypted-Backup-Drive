import struct
import uuid
from datetime import datetime
from Response import Response
from Crypto.Cipher import AES 
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP
from DatabaseMaintenance import client_database 
import crypto 
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def crc8(data):
    crc = 0
    for i in range(len(data)):
        byte = data[i]
        for b in range(8):
            fb_bit = (crc ^ byte) & 0x01
            if fb_bit == 0x01:
                crc = crc ^ 0x18
            crc = (crc >> 1) & 0x7f
            if fb_bit == 0x01:
                crc = crc | 0x80
            byte = byte >> 1
    return crc


class Request:
    def __init__(self, stream):
        self.client_id = stream[0:16]
        self.version = int.from_bytes(stream[16:17], "little")
        self.code = struct.unpack_from("H", stream, 17)[0]
        self.payload_size = int.from_bytes(stream[19:23], "little")
        self.payload = stream[23:]

    def __repr__(self):
        return "Version " + str(self.version) + " Code: " + str(self.code) + " PayloadSize: " + str(self.payload_size)


def register(payload):
    uu = uuid.uuid4()
    print("Insert new client")
    print("uu bytes",uu.bytes)
    return Response(1, 2100, 23, uu.bytes), uu



def recieve_pub_key(payload, aes_key):
    public_key = payload[255:415]
    name = str(payload[0:255], 'UTF-8')
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_aes = cipher.encrypt(aes_key)
    print("encypted aes len is:" , len(encrypted_aes), "\n")
    cl_db = client_database()
    uu = cl_db.get_uuid_from_name(payload)
    cl_db.update_db_with_keys(str(uu), str(public_key),str(encrypted_aes) )
    payload = bytearray()
    payload+=uu.bytes
    payload+=encrypted_aes
    return Response(1, 2102, 151, payload)



def recieve_encrypted_file(payload, aes_key):
    print(payload)
    cl_db = client_database()
    uu = payload[0:16]
    content_size =  int.from_bytes(payload[16:20], "little")
    print("content_size:", content_size)
    file_name = payload[20:275]
    print("file_name:", file_name.decode("utf-8"))
    file_name_decoded = file_name.decode("utf-8")
    file_content = payload[275:275+content_size]
    print("file content:", file_content)
    iv = bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    full_unpad_dec = bytearray()
    decrypted_file = cipher.decrypt(file_content)
    print("decrypted file full:", decrypted_file)
    full_unpad_dec = unpad(decrypted_file, 16)
    checksum = crc8(full_unpad_dec)      
    print("checksum:", checksum)
    payload = bytearray()
    payload+=uu
    content_size=len(decrypted_file)
    payload+=content_size.to_bytes(4, byteorder='little')
    payload+=file_name
    payload+=checksum.to_bytes(4, byteorder='little') 
    return Response(1, 2103, 286, payload), full_unpad_dec, file_name_decoded
    
    
def successful_file_transfer(payload):
    file_name = payload[16:271]
    cl_db = client_database()
    print( "The client has sent file", file_name.decode("utf-8"), "successfully")
    payload = bytearray()
    return Response(1, 2104, 7, payload)
    
    
def fail_file_transfer(payload):
    file_name = payload[16:271]
    cl_db = client_database()
    print( "Failed file transfer")
    payload = bytearray()
    return Response(1, 2101, 7, payload)
    