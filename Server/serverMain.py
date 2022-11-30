import sys
import socket
from threading import Thread
import uuid
from Request import Request
from Response import Response
import Request as ReqHandler
from DatabaseMaintenance import client_database 
from Crypto.Cipher import AES
import crypto
import os
from io import BytesIO

def create_file_directory():
    directory = "BackedUpFiles"
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    parent_dir = str(ROOT_DIR)
    final_path = os.path.join(parent_dir, directory)
    #if directory doesnt exist already
    if not os.path.isdir(final_path):
        os.makedirs(final_path)
    print("Directory '% s' created" % directory)
    return final_path

def add_file_2Dir(dir_path, file_name, file_data):
    
    file_path = os.path.join(dir_path, file_name)
    changed_file_path = (file_path.replace("\\", "\\\\")).rstrip(' \t\r\n\0')
    print("changed file", changed_file_path)
    binary_file = open(changed_file_path, "wb")
    binary_file.write(file_data)
    print("File added to directory successfully")
    
    

def read_port():
    portFile = open("port.info", "r")
    port = int(portFile.read())
    return port

def handle_client(connection, client_address, aes_key, dir_path):
    print("aes key:", aes_key.hex(), "\n")
    print("Establish new connection with client", client_address)
    request_stream = connection.recv(1024)
    print ("Incoming request content:", request_stream)
    request = Request(request_stream)
    file_name_decoded = ""
    decrypted_file_data = b''
    
    print("request.code = ", request.code)
    if request.code == 1100:
        # Get requset from type "Register"
        response,uu = ReqHandler.register(request.payload)
        print( "uu is:", uu, "\n")
        cl_db = client_database()
        cl_db.add_register_client(request.payload,uu)
        #print(RegisteredClientsMap)
        if response is not None:
            connection.send(response.stream)
            
    if request.code == 1101:
        # recieve public key and send AES key
        response = ReqHandler.recieve_pub_key(request.payload, aes_key)
        cl_db = client_database()
        if response is not None:
            print("sending response 2102")
            connection.send(response.stream)
            
    if request.code == 1103:
            # Get requset from type "SendMessage"
            response,decrypted_file_data, file_name_decoded= ReqHandler.recieve_encrypted_file(request.payload, aes_key)
            if response is not None:
                print("sending response 2103")
                add_file_2Dir(dir_path, file_name_decoded, decrypted_file_data)
                connection.send(response.stream)
                
    if request.code == 1104:
        # Get request from type "SendMessage"
        response = ReqHandler.successful_file_transfer(request.payload)
        cl_db = client_database()
        cl_db.add_file(request.payload,1,dir_path)
        if response is not None:
            connection.send(response.stream)
            print("Sent success")
            
    if request.code == 1105:
        print("client needs to send message again")
        response = ReqHandler.fail_file_transfer(request.payload)
        if response is not None:
            connection.send(response.stream)
            
    if request.code == 1106:
        print("Corrupted file after fourth sending")
        response = ReqHandler.fail_file_transfer(request.payload)
        if response is not None:
            connection.send(response.stream)
    connection.close()

def start_server(port,aes_key,dir_path):
    
    sock = socket.socket()              # Create scoket object
    host = socket.gethostname()         # Get local name

    sock.bind((host, port))             # Bind socket to port
    sock.listen(5)                      # Wait fo client connection

    while True:
        print("wait for client...")
        connection, client_address = sock.accept()  # Establish connection with client
        
        #print(RegisteredClientsMap)
        handler =Thread(target=handle_client, args=(connection, client_address,aes_key, dir_path))
        handler.start()


def main():
    print("Server...")
    port = read_port()
    print("Server listen on port", port)
    aes_key = crypto.generate_aes_key()
    dir_path = create_file_directory()
    start_server(port,aes_key, dir_path)

if __name__ == "__main__":
    main()