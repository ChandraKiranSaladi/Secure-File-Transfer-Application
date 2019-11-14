import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import SHA256
import zlib
import uuid
import random 

class Client:

    def __init__(self):
        self.socket = ''

    def set_keys(self,k1,k2,k3,k4):
        self.k1 = k1
        self.k2 = k2
        self.k3 = k3
        self.k4 = k4

    def server_authentication(self,public_key):
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
        # self.socket.send(len(initial_conn_string))
        self.socket.send(initial_conn_string)
        length = self.bytes_to_int(self.socket.recv(2))
        msg = self.socket.recv(length)
        integrity = msg[32:]
        msg = msg[:32]

        #signature verification, if wrong throws a value error
        # TODO: catch for Value Errors
        # try:
        pss.new(rsa_public_key).verify(SHA256.new(msg), integrity)
        # except ValueError as e:
        #     print("Integrity cannot be verified\n Authentication unsuccessful" , str(e))
        sha = SHA256.new("Bob".encode() + Na.bytes).digest()
        Nb =  unpad(strxor(sha,msg),32)
        session_key = strxor(Na,Nb)

        return session_key

    
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

    def initiate_connection(self):
        """
        Initiates socket connection

        Returns:

         - s: socket
        """
        s = socket.socket()
        s.connect(("localhost",5543))
        print("Connection established")
        self.socket = s
    
    def send_seqA_num(self):
        """
        Generates random sequence number and send it as 
        keyed hash
        msg1 : send seq number using keyed hash  
        msg2: for server side to check integrity of msg1
        """
        # FIXME: seqA and seqB 32 bits? step4 include seqA in hash?
        seq = random.randint(1000000000,9999999999)
        seq_bytes = self.int_to_bytes(seq,32)
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

       
    def close_connection(self):
        self.socket.close()


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
        key_string = "Alice".encode()+self.k1
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
                msg = strxor(SHA256.new("Bob".encode()+self.k1+self.int_to_bytes(seqB)),recv_msg[:32])
                
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

    def receive_file(self):
        pass

if __name__ == '__main__':
    client = Client()
    client.initiate_connection()
    f_pubk = open('public_key.pem', 'rb')
    public_key = f_pubk.read()
    f_pubk.close()
    try: 
        session_key = client.server_authentication(public_key)
        session = client.bytes_to_int(session_key)
        k1 = client.int_to_bytes(session + 2)
        k2 = client.int_to_bytes(session + 5)
        k3 = client.int_to_bytes(session + 7)
        k4 = client.int_to_bytes(session + 9)
        client.set_keys(k1,k2,k3,k4)
        exit_flag = False
        while not exit_flag:
            # TODO: Step 3 and 4 inside send_file and different sequence numbers for each file
            client.send_file('input_directory/izuku.jpg')
            exit_flag = input("Continue?") == "False"
    except Exception as e:
        print(str(e))
    finally:
        client.close_connection()

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

f = open("/home/rik/netsec/Secure-File-Transfer-Application/input_directory/izuku.jpg", "rb")
# s.send('encrypted_img.jpg'.encode('utf-8'))
l = f.read(1024)
while (l):
    s.send(l)
    l = f.read(1024)
# s.close()
