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

class Server:
    
    def __init__(self,socket):
        self.socket = socket
        self.k1 = 0
        self.k2 = 0
        self.k3 = 0
        self.k4 = 0

    def set_keys(self,k1,k2,k3,k4):
        self.k1 = k1
        self.k2 = k2
        self.k3 = k3
        self.k4 = k4

    def send_ack_initial_connection(self,private_key):
        """
        * Responds to the client connection

        """
        rsa_private_key = RSA.importKey(private_key)
        rsa_key = PKCS1_OAEP.new(rsa_private_key)
        Nb = uuid.uuid4()
        encrypted_msg = self.socket.receive(512)
        msg = rsa_key.decrypt(encrypted_msg)
        name = msg[-5:]
        print(name)
        # if msg[-5:] != "Alice":
        #     conn.close()
        Na = msg[:-5]
        print("Na recv", Na)
        msg = "Bob".encode() + Na.bytes
        sha = SHA256.new(msg)
        # print("len sha ",len(sha.digest()) )
        # print("len Nb ",len(Nb.encode()))
        # print("pad length ",len(pad(Nb.bytes,32)))
        msg = strxor(sha.digest(),pad(Nb.bytes,32))
        integrity = pss.new(rsa_private_key).sign(SHA256.new(msg))
        length = len(msg) + len(integrity)
        self.socket.send(self.int_to_bytes(length,2))
        self.socket.send(msg)
        self.socket.send(integrity)
        session = strxor(Na,Nb.bytes)
        return session

    # return msg
    # conn.send(rsa_key.encrypt(msg))


    def send_seqA_num(self):
        """
        Generates random sequence number and send it as 
        keyed hash
        msg1 : send seq number using keyed hash  
        msg2: for server side to check integrity of msg1
        """
        # FIXME: seqA and seqB 32 bits? step4 include seqA in hash?
        seq = random.randint(1000000000,9999999999)
        seq_bytes = self.int_to_bytes(seq)
        msg = "Alice".encode()+self.k1
        sha = SHA256.new(msg)
        msg = strxor(sha.digest(),seq_bytes)
        sha_integrity = SHA256.new(msg+self.k2)
        #send the message and hash of message(32 bytes each)
        self.socket.send(msg)
        self.socket.send(sha_integrity.digest())
        return seq
    
    def recv_seqB(self, msg):
        '''
        Calculates the server side initial seq number 
        returns the server seq number as int
        '''
        integrity = msg[33:]
        msg = msg[:32]
        sha_integrity = SHA256.new(msg+self.k2)
        if  not sha_integrity.digest() == integrity:
            print('message is tampered')
        key_string = "Bob".encode()+self.k1
        sha = SHA256.new(key_string)
        #received seq number in bytes 
        recv_seq = strxor(msg , sha.digest())
        seq = self.bytes_to_int(recv_seq)
        #verified till previous line ; we got back seq number
        return seq

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

    def int_to_bytes(self,data,length=16):
        """
            Converts integer to bytes

            Returns:
                bytes 
        """
        return data.to_bytes(length,byteorder='big')

    def close_connection(self):
        self.socket = None
    
    def receive_file(self,path):
        pass
    
    def send_file(self,path):
        # TODO: File transfer gets corrupted and the file retransmission is required in the middle of 
        # exchange
        
        #send 3rd message
        seqA = self.send_seqA_num()
        #receive 4th message
        recv_seqB_msg = self.socket.recv(64)
        seqB = self.recv_seqB(recv_seqB_msg)
        f_file = open(path, 'rb')
        file_data= f_file.read()
        f_file.close()
        #compress the data first
        # file_data = zlib.compress(file_data)
        #will encrypt and decrypt chunks at a time
        chunk_size = 32
        key_string = "Bob".encode()+self.k1
        offset = 0
        end_loop = False

        while not end_loop:
            #The chunk
            chunk = file_data[offset:offset + chunk_size]
            trial_count = 2
            while trial_count > 0 and trial_count < 2:
                #If the data chunk is less then the chunk size, then we need to add
                #padding with " ". This indicates the we reached the end of the file
                #so we end loop here
                if len(chunk) % chunk_size != 0:
                    end_loop = True
                    chunk += pad(chunk,chunk_size - len(chunk))

                # Encryption using SHA
                encrypted_msg = strxor(SHA256.new(key_string+ self.int_to_bytes(seqA)),chunk)
                self.socket.send(len(chunk))
                self.socket.send(encrypted_msg)
                integrity = SHA256.new(encrypted_msg+self.int_to_bytes(k2))
                self.socket.send(integrity)

                # TODO: receive message from server anc check for integrity
                recv_msg = self.socket.recv(64)
                integrity = SHA256.new(recv_msg[33:]+self.int_to_bytes(k2))
                msg = strxor(SHA256.new("Alice".encode()+self.k1+self.int_to_bytes(seqB)),recv_msg[:32])
                
                if msg != "Ok".encode():
                    trial_count -= 1
                #Increase the offset by chunk size
                seqA += 1
                seqB += 1

            if trial_count == 0:
                end_loop = True
            offset += chunk_size

        #Base 64 encode the encrypted file
        # return base64.b64encode(encrypted)


if __name__ == '__main__':
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
        try:
            session_key = server.send_ack_initial_connection(private_key)
            session = server.bytes_to_int(session_key)
            k1 = server.int_to_bytes(session + 2)
            k2 = server.int_to_bytes(session + 5)
            k3 = server.int_to_bytes(session + 7)
            k4 = server.int_to_bytes(session + 9)
            server.set_keys(k1,k2,k3,k4)
            server.receive_file("./output_directory")
        except Exception as e:
            print(str(e))
        finally:
            server.socket.close()

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
