import socket
import sys
import pandas
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import SHA256
import zlib
import uuid

class Client:

    def server_authentication(self,public_key,conn):
        """
        Authenticates server to the client
        --- 
        * public_key: RSA Public key
        * conn: socket connection

        Returns:

        * session Key -> bytes

        """
        rsa_public_key = RSA.importKey(public_key)
        rsa_key = PKCS1_OAEP.new(rsa_public_key)
        Na = uuid.uuid4()
        print("Na ",Na)
        initial_conn_string = rsa_key.encrypt(Na.bytes+"Alice".encode())
        print(initial_conn_string)

        # return initial_conn_string
        # conn.send(initial_conn_string)
        msg,integrity = conn.recv()

        #signature verification, if wrong throws a value error
        # TODO: catch for Value Errors
        pss.new(rsa_public_key).verify(SHA256.new(msg), integrity)

        sha = SHA256.new("Alice".encode() + Na.bytes).digest()
        Nb =  unpad(strxor(sha,msg),32)
        session_key = strxor(Na,Nb)

        return session_key

        
    def encrypt_file(self,public_key, file_data):

        #compress the data first
        file_data = zlib.compress(file_data)
        #will encrypt and decrypt chunks at a time
        chunk_size = 470
        offset = 0
        end_loop = False
        encrypted = ""
        while not end_loop:
            #The chunk
            chunk = file_data[offset:offset + chunk_size]

            #If the data chunk is less then the chunk size, then we need to add
            #padding with " ". This indicates the we reached the end of the file
            #so we end loop here
            if len(chunk) % chunk_size != 0:
                end_loop = True
                chunk += " " * (chunk_size - len(chunk))

            #Append the encrypted chunk to the overall encrypted file
            encrypted += rsa_key.encrypt(chunk)

            #Increase the offset by chunk size
            offset += chunk_size

        #Base 64 encode the encrypted file
        # return base64.b64encode(encrypted)

    def initiate_connection(self):
        """
        Initiates socket connection

        Returns:

         - s: socket
        """
        s = socket.socket()
        s.connect(("localhost",5543))
        print("Connection established")
        return s

def __init__():
    client = Client()
    s = client.initiate_connection()
    f_pubk = open('public_key.pem', 'rb')
    public_key = f_pubk.read()
    f_pubk.close()
    session_key = client.server_authentication(public_key,s)
    

# print('Encrypting file...')
# rsa_key = RSA.importKey(public_key)
# initial_string = rsa_key.encrypt(Na+"Alice")
# f_file = open('input_directory/izuku.jpg', 'rb')
# data= f_file.read()
# f_file.close()
# encrypted_data = encrypt_file(public_key, data)
# fd = open("encrypted_img.jpg", "wb")
# fd.write(encrypted_data)
# fd.close()

# f = open ("/home/rik/netsec/Secure-File-Transfer-Application/input_directory/izuku.jpg", "rb")
# s.send('encrypted_img.jpg'.encode('utf-8'))
# l = f.read(1024)
# while (l):
#     s.send(l)
#     l = f.read(1024)
# s.close()
