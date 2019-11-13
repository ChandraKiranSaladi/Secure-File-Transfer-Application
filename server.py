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
import random

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
    
    def __init__(self):
        self.k1 = 0
        self.k2 = 0
        self.k3 = 0
        self.k4 = 0

    def set_keys(self,k1,k2,k3,k4):
        self.k1 = k1
        self.k2 = k2
        self.k3 = k3
        self.k4 = k4

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
        session = strxor(Na,Nb.bytes)
        conn.send(length)
        return session

    # return msg
    # conn.send(rsa_key.encrypt(msg))
    def bytes_to_int(self,data):
        """
            Converts bytes to integer

            Returns:
                int  
        """
        result = 0
        for b in data:
            result += result*256 + int(b)

        return result

    def int_to_bytes(self,data):
        """
            Converts integer to bytes

            Returns:
                bytes 
        """
        return data.to_bytes(16,byteorder='big')
    def recv_seq_one (self, recv_msg1, key1): 
        """
        Retrieves the the sequence number of client 
        Returns : client sequence number
        """
        msg = key1 + "Alice".encode()
        sha = SHA256.new(msg)
        #received seq number in bytes 
        recv_seq = strxor(recv_msg1 , sha.digest())
        seq = self.bytes_to_int(recv_seq)
        #verified till previous line ; we got back seq number
        return seq


        
    def recv_seq_two(self, recv_msg2,recv_msg1,  key2):
        """
        Checks integrity of incoming message 
        """

        sha_integrity = SHA256.new(recv_msg1+key2)
        return  sha_integrity.digest()== recv_msg2
        #verified 






    def send_seq_num(self,sock,  key1, key2):
        seq = random.randint(1000000000,9999999999)
        seq_bytes = seq.to_bytes(32,byteorder='big')
        msg = key1+ "Bob".encode()
        sha = SHA256.new(msg)
        msg = strxor(sha.digest(),seq_bytes)
        sha_integrity = SHA256.new(msg+key2)
        sock.send(msg)
        sock.send(sha_integrity.digest())

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
    f_pubk = open('private_key.pem', 'rb')
    private_key = f_pubk.read()
    f_pubk.close()
    while True:
        sock, address = s.accept()
        print("Connection accepted from ",address)
        server = Server(sock)
        # TODO: receive bytes from client
        msg = sock.recv(32)
        session_key = server.send_ack_initial_connection(msg,private_key,sock)
        session = server.bytes_to_int(session_key)
        k1 = server.int_to_bytes(session + 2)
        k2 = server.int_to_bytes(session + 5)
        k3 = server.int_to_bytes(session + 7)
        k4 = server.int_to_bytes(session + 9)
        #receive 3rd message 
        recv_seq_msg_one = sock.recv(32)
        recv_seq_msg_two = sock.recv(32)
        client_seq_int = server.recv_seq_one(recv_seq_msg_one, k1)
        integrity_check = server.recv_seq_two(recv_seq_msg_two, recv_seq_msg_one , k2)
        if integrity_check:
            pass
        else:
            print('message is tampered')
        #send 4th message
        server.send_seq_num(sock, k1, k2)


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
