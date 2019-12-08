import socket
import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from Crypto.Signature import pss
from Crypto.Hash import SHA256
# import zlib
import uuid
import traceback

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
        self.command_list = ["Upload","Download","List","End","Exit"]

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
        encrypted_msg = self.socket.recv(512)
        msg = rsa_key.decrypt(encrypted_msg)
        name = msg[-5:]
        print(name)
        # if msg[-5:] != "Alice":
        #     conn.close()
        Na = msg[:-5]
        print("Na recv", Na)
        print("Nb ",Nb.bytes)
        msg = "Bob".encode() + Na
        sha = SHA256.new(msg)
        # print("len sha ",len(sha.digest()) )
        # print("len Nb ",len(Nb.encode()))
        # print("pad length ",len(pad(Nb.bytes,32)))
        msg = strxor(sha.digest(),pad(Nb.bytes,32))
        integrity = pss.new(rsa_private_key).sign(SHA256.new(msg))
        length = 32 + 512
        self.socket.send(self.int_to_bytes(length,2))
        self.socket.send(msg+integrity)
        # self.socket.send(integrity)
        session = strxor(Na,Nb.bytes)
        return session

    # return msg
    # conn.send(rsa_key.encrypt(msg))


    def recv_seqA_send_seqB(self):
        """
        Receives seqA: random number from client and sends seqB
        as encrypted message to server

        Returns:
            - seqA : 32 byte integer
            - seqB : 32 byte integer
        """
        msg = self.socket.recv(64)
        sha_key_string = "Alice".encode()+self.k1
        seqA_bytes = self.get_decrypted_msg(msg,sha_key_string, self.k2)
        seqA = int.from_bytes(seqA_bytes, byteorder='big')
        print("seqA recv: ",seqA)

        seqB_bytes = get_random_bytes(32)
        seqB = int.from_bytes(seqB_bytes, byteorder='big')
        print("sending seqB ",seqB)
        key_string = "Bob".encode()+self.k1
        #send the message and hash of message(32 bytes each)
        msg = self.get_encrypted_msg_with_integrity(seqB_bytes,key_string, self.k2)
        self.socket.send(msg)
        return seqA, seqB
       
    def close_connection(self):
        self.socket.close()

    def get_encrypted_msg_with_integrity(self,msg,sha_key_string, sha_integrity_key_string):
        """
            Generates encrypted message and integrity information in bytes

            - msg: Input message in bytes
            - sha_key_string : key in bytes
            - sha_integrity_key_string: Integrity key in bytes
            Returns:
                - bytes : 64 byte message with encrypted and integrity messages 
        """
        if(len(msg) != 32):
            msg = pad(msg,32)
        encrypted_msg = strxor(SHA256.new(sha_key_string).digest(),msg)
        integrity = SHA256.new(msg+sha_integrity_key_string).digest()
        return encrypted_msg + integrity

    def get_decrypted_msg(self,msg,sha_key_string, sha_integrity_key_string):
        integrity = msg[32:]
        msg = msg[:32]
        decrypted_msg = strxor(SHA256.new(sha_key_string).digest(),msg)

        sha_integrity = SHA256.new(decrypted_msg+sha_integrity_key_string).digest()

        if  not sha_integrity == integrity:
            print("Message is tampered")
            raise ValueError('message is tampered')
     
        #received seq number in bytes 
        return decrypted_msg

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
        return data.to_bytes(length,byteorder='big')[-length:]
    
    def respond_to_client_command(self):

        while True:
            seqA,seqB = self.recv_seqA_send_seqB()
            seqA += 1
            seqB += 1
            command,file_name = self.get_command(self.socket.recv(64),seqA,seqB,self.k1,self.k2)
            if command in self.command_list and command != "Exit":
                self.send_command("Ok",seqA,seqB, self.k1, self.k2)
                seqA += 1
                seqB += 1
       
            if command == "Download":
                f = open("./server_directory/"+file_name, 'rb')
                file_data= f.read()
                f.close()
                #Using k3 and k4 for download 
                seqA, seqB = self.send_data(file_data,seqA,seqB, self.k3, self.k4)

            elif command == "Upload":
                #using k1 and k2 for upload
                data = self.receive_data(seqA,seqB,self.k1, self.k2)
                f = open('./server_directory/'+file_name,"wb")
                f.write(data)
                f.close()

            elif command == "List":
                file_list =  os.listdir("./server_directory")
                file_list = ";".join([file_name for file_name in file_list])
                self.send_data(file_list.encode(), seqA, seqB, self.k1, self.k2)                
                
            elif command == "Exit":
                return
            else:
                continue
            # Wait for SeqA
            # Send SeqB
            # wait for command
            # reply back accodingly
            # Receive or send
            # if close then continue

    def receive_data(self,seqA,seqB, encryption_key, integrity_key):
        data = b''
        while True:
            
            msg = self.get_decrypted_msg(self.socket.recv(64),"Alice".encode()+encryption_key+self.int_to_bytes(seqA,32),integrity_key+self.int_to_bytes(seqA,32))
            chunk_length = self.bytes_to_int(msg[0:2])
            chunk = msg[2:2+chunk_length]
            try:
                if chunk[0:3].decode() == "End":
                    self.send_command("Ok",seqA,seqB,encryption_key, integrity_key)
                    seqA += 1
                    seqB += 1
                    break
            except UnicodeDecodeError:
                pass
            self.send_command("Ok",seqA,seqB, encryption_key, integrity_key)
            data += chunk
            # print(" len file_data: ",len(file_data))
            seqA += 1
            seqB += 1
            
        return data


    def get_command(self,msg,seqA,seqB, encryption_key, integrity_key):
        # TODO: Account for listing Directories
        msg = self.get_decrypted_msg(msg,"Alice".encode()+encryption_key+self.int_to_bytes(seqA,32), integrity_key+self.int_to_bytes(seqA,32))
        msg_length = self.bytes_to_int(msg[0:2])
        msg_chunk = msg[2:2+msg_length].decode()
        msg_list = msg_chunk.split(",")

        arr = msg_list [0]
        command = arr
        if command == "Download" or command == "Upload":
            filename = msg_list[1]


        #arr,file_name = msg_chunk.split(",")
        #command = arr 
        if command not in self.command_list:
            print("Unknown Command")
            # TODO: If command is unknown handle it by sending command Unknown
            # self.send_command(seqA,seqB)
        if command == "Download" or command == "Upload":
            return command,filename
        else:
            return command, ""

    def send_command(self,command,seqA,seqB, encryption_key, integrity_key):
        """
            Sends command to the Client and waits for acknowledgement

            - command: str
            - seqA : int
            - seqB : int
            - encryption_key : key for encryption
            - decryption_key : key for decryption

        """
        command_chunk = command.encode()
        command_chunk = self.int_to_bytes(len(command_chunk),2) + command_chunk
        msg = self.get_encrypted_msg_with_integrity(command_chunk,"Bob".encode()+encryption_key+self.int_to_bytes(seqB,32), integrity_key+self.int_to_bytes(seqB,32))
        self.socket.send(msg)

        if command == "End":
            recv_msg = self.socket.recv(64)
            msg = self.get_decrypted_msg(recv_msg,"Alice".encode()+encryption_key+self.int_to_bytes(seqA,32),integrity_key+self.int_to_bytes(seqA,32))
            ack_length = self.bytes_to_int(msg[0:2])
            ack_chunk = msg[2:2+ack_length]
            if "Ok".encode() != ack_chunk:
                print("Ack_Chunk: ", ack_chunk)
                print("Command not received")
                raise Exception("Command not received")

    def send_data(self,data,seqA, seqB, encryption_key, integrity_key):
        """
            Sends data to Client in encrypted channel

            - data: bytes 
            - seqA: int 
            - seqB: int
            - encryption_key : key for encryption
            - decryption_key : key for decryption

        """

        # TODO: File transfer gets corrupted and the file retransmission is required in the middle of 
        # exchange

        #will encrypt and decrypt chunks at a time
        chunk_size = 30
        key_string = "Bob".encode()+encryption_key
        offset = 0
        end_loop = False

        while not end_loop:
            #The chunk
            chunk = data[offset:offset + chunk_size]
            # print("Offset ",offset)
            trial_count = 2
            while trial_count > 0 and trial_count <= 2:
                #If the data chunk is less then the chunk size, then we need to add
                #padding with " ". This indicates the we reached the end of the file
                #so we end loop here
                if len(chunk) % chunk_size != 0 or len(chunk) == 0:
                    end_loop = True

                chunk = self.int_to_bytes(len(chunk),2) + chunk
                # Encryption using SHA
                msg = self.get_encrypted_msg_with_integrity(chunk,key_string+self.int_to_bytes(seqB,32), integrity_key+self.int_to_bytes(seqB,32))
                self.socket.send(msg)

                recv_msg = self.socket.recv(64)
                msg = self.get_decrypted_msg(recv_msg,"Alice".encode()+encryption_key+self.int_to_bytes(seqA,32),integrity_key+self.int_to_bytes(seqA,32))
                ack_length = self.bytes_to_int(msg[0:2])
                ack_chunk = msg[2:2+ack_length]
                if ack_chunk != "Ok".encode():
                    trial_count -= 1
                #Increase the offset by chunk size
                seqA += 1
                seqB += 1
                if trial_count == 2:
                    break
            if trial_count == 0:
                end_loop = True
            offset += chunk_size
        
        self.send_command("End",seqA,seqB,encryption_key, integrity_key)
        return seqA,seqB
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
            print("session: ", session)
            k1 = server.int_to_bytes(session + 2)
            k2 = server.int_to_bytes(session + 5)
            k3 = server.int_to_bytes(session + 7)
            k4 = server.int_to_bytes(session + 9)
            server.set_keys(k1,k2,k3,k4)
            server.respond_to_client_command()
        except Exception as e:
            print('Socket closed')
            # traceback.print_exc()
            # print(str(e))
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

#     f= open("/home/rik/netsec/Secure-File-Transfer-Application/server_directory/"+file_name,'wb')
#     l = 1
#     while (l):       
#         # receive data and write it to file
#         l =  sock.recv(1024)
#         while (l):
#                 f.write(l)
#                 l =  sock.recv(1024)
#         print("I'm Done Here ")
# s.close()
