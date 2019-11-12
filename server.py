import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import zlib
import uuid

'''
Generate RSA public/private key of server
'''
def generate_key():
    """
        Generates RSA Public Private key pair and stores it in public_key.pem \n
        and private_key.pem files in the current directory

    """
    print('inside generate key')
    new_key = RSA.generate(4096, e=65537)
    private_key = new_key.exportKey("PEM")

    #The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")

    print (private_key)
    fd = open("private_key.pem", "wb")
    fd.write(private_key)
    fd.close()

    print (public_key)
    fd = open("public_key.pem", "wb")
    fd.write(public_key)
    fd.close()

class Server(socket):
    
    def send_ack_initial_connection(self,encrypted_msg,private_key,conn):
        """
        * Responds to the client connection

        """
        rsa_private_key = RSA.importKey(private_key)
        rsa_key = PKCS1_OAEP.new(rsa_private_key)
        Nb = uuid.uuid4()
        # msg = conn.receive(512)
        msg = rsa_key.decrypt(encrypted_msg)
        name = msg[-5:]
        print(name)
        # if msg[-5:] != "Alice":
        #     conn.close()
        Na = msg[:-5]
        print("Na recv", Na)
        msg = name + Na
        sha = SHA256.new(msg)
        print("len sha ",len(sha.digest()) )
        # print("len Nb ",len(Nb.encode()))
        print("pad length ",len(pad(Nb.bytes,32)))
        msg = strxor(sha.digest(),pad(Nb.bytes,32))
        integrity = pss.new(rsa_private_key).sign(SHA256.new(msg))
        length = len(msg) + len(integrity)
        conn.send(length)

    # return msg
    # conn.send(rsa_key.encrypt(msg))

    def encrypt_file(self,public_key, file_data):
        rsa_key = RSA.importKey(public_key)
        rsa_key = PKCS1_OAEP.new(rsa_key)

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

def __init__():
    s = socket.socket()
    s.bind(("localhost",5543))
    s.listen(10)
    while True:
        sock, address = s.accept()
        print("Connection accepted from ",address)
        server = Server(sock)
        server.send_ack_initial_connection


# generate_key()
# while True:
#     sock, address = s.accept()

#     print("Connection accepted from ",address)

#     #File Name
#     file_name = sock.recv(1024).decode('utf-8')
#     print('file received with file_name')
#     print(file_name)

#     f= open("/home/rik/netsec/Secure-File-Transfer-Application/output_directory/"+file_name,'wb')
#     l = 1
#     while (l):       
#         # receive data and write it to file
#         l =  sock.recv(1024)
#         while (l):
#                 f.write(l)
#                 l =  sock.recv(1024)
#         print("I'm Done Here ")
# s.close()
