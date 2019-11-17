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


    def send_seqB_num(self):
        """
        Generates random sequence number and send it as 
        keyed hash
        msg1 : send seq number using keyed hash  
        msg2: for server side to check integrity of msg1
        """
        seqB_bytes = get_random_bytes(32)
        seqB = int.from_bytes(seqB_bytes, byteorder='big')
        print("sending seqB ",seqB)
        key_string = "Bob".encode()+self.k1
        #send the message and hash of message(32 bytes each)
        msg = self.get_encrypted_msg_with_integrity(seqB_bytes,key_string)
        self.socket.send(msg)
        return seqB
    
    def recv_seqA(self):
        '''
        Calculates the server side initial seq number 
        returns the server seq number as int
        '''
        msg = self.socket.recv(64)
        sha_integrity_key_string = "Alice".encode()+self.k1
        seqA_bytes = self.get_decrypted_msg(msg,sha_integrity_key_string)
        seqA = int.from_bytes(seqA_bytes, byteorder='big')
        print("seqA recv: ",seqA)
        #verified till previous line ; we got back seq number
        return seqA

       
    def close_connection(self):
        self.socket.close()

    def get_encrypted_msg_with_integrity(self,msg,sha_key_string):
        if(len(msg) != 32):
            msg = pad(msg,32)
        encrypted_msg = strxor(SHA256.new(sha_key_string).digest(),msg)
        integrity = SHA256.new(encrypted_msg+self.k2).digest()
        return encrypted_msg + integrity

    def get_decrypted_msg(self,msg,sha_key_string):
        integrity = msg[32:]
        msg = msg[:32]
        sha_integrity = SHA256.new(msg+self.k2).digest()

        if  not sha_integrity == integrity:
            raise ValueError('message is tampered')
        
        #received seq number in bytes 
        decrypted_msg = strxor(SHA256.new(sha_key_string).digest(),msg)
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
            seqA = self.recv_seqA()
            seqB = self.send_seqB_num()
            seqA += 1
            seqB += 1
            command,file_name = self.get_command(self.socket.recv(64),seqA,seqB)
            if command in self.command_list and command != "Exit":
                self.send_command("Ok",seqA,seqB)
                seqA += 1
                seqB += 1
            if command == "Download":
                seqA, seqB = self.send_file('./server_directory/'+file_name,seqA,seqB)
            elif command == "Upload":
                seqA, seqB = self.receive_file('./server_directory/'+file_name,seqA,seqB)
            elif command == "List":
                filename_list = ""
                dir_obj =  os.scandir()
                for ele in dir_obj:
                    filename_list = filename_list + ele.name + ';'
                self.send_list (filename_string.encode(), seqA, seqB)                
                
                

                # TODO: Send files to Client

                pass
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

    def receive_file(self,path,seqA,seqB):
        file_data = b''
        while True:
            msg = self.get_decrypted_msg(self.socket.recv(64),"Alice".encode()+k1+self.int_to_bytes(seqA,32))
            chunk_length = self.bytes_to_int(msg[0:2])
            chunk = msg[2:2+chunk_length]
            try:
                if chunk[0:3].decode() == "End":
                    self.send_command("Ok",seqA,seqB)
                    seqA += 1
                    seqB += 1
                    break
            except UnicodeDecodeError:
                pass
            self.send_command("Ok",seqA,seqB)
            file_data += chunk
            # print(" len file_data: ",len(file_data))
            seqA += 1
            seqB += 1
        f = open(path,"wb")
        f.write(file_data)
        f.close()
        return seqA, seqB

    def get_command(self,msg,seqA,seqB):
        # TODO: Account for listing Directories
        msg = self.get_decrypted_msg(msg,"Alice".encode()+self.k1+self.int_to_bytes(seqA,32))
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

    def send_command(self,command,seqA,seqB):
        command_chunk = command.encode()
        command_chunk = self.int_to_bytes(len(command_chunk),2) + command_chunk
        msg = self.get_encrypted_msg_with_integrity(command_chunk,"Bob".encode()+self.k1+self.int_to_bytes(seqB,32))
        self.socket.send(msg)

        if command == "End":
            recv_msg = self.socket.recv(64)
            msg = self.get_decrypted_msg(recv_msg,"Alice".encode()+self.k1+self.int_to_bytes(seqA,32))
            ack_length = self.bytes_to_int(msg[0:2])
            ack_chunk = msg[2:2+ack_length]
            if "Ok".encode() != ack_chunk:
                print("Ack_Chunk: ", ack_chunk)
                raise Exception("Command not received")

    def send_file(self,path,seqA, seqB):
        # TODO: File transfer gets corrupted and the file retransmission is required in the middle of 
        # exchange
        f_file = open(path, 'rb')
        file_data= f_file.read()
        f_file.close()
        #compress the data first
        # file_data = zlib.compress(file_data)
        #will encrypt and decrypt chunks at a time
        chunk_size = 30
        key_string = "Bob".encode()+self.k1
        offset = 0
        end_loop = False

        while not end_loop:
            #The chunk
            chunk = file_data[offset:offset + chunk_size]
            print("Offset ",offset)
            trial_count = 2
            while trial_count > 0 and trial_count <= 2:
                #If the data chunk is less then the chunk size, then we need to add
                #padding with " ". This indicates the we reached the end of the file
                #so we end loop here
                if len(chunk) % chunk_size != 0 or len(chunk) == 0:
                    end_loop = True

                chunk = self.int_to_bytes(len(chunk),2) + chunk
                # Encryption using SHA
                msg = self.get_encrypted_msg_with_integrity(chunk,key_string+self.int_to_bytes(seqB,32))
                self.socket.send(msg)

                recv_msg = self.socket.recv(64)
                msg = self.get_decrypted_msg(recv_msg,"Alice".encode()+self.k1+self.int_to_bytes(seqA,32))
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
        
        self.send_command("End",seqA,seqB)
        return seqA,seqB
        #Base 64 encode the encrypted file
        # return base64.b64encode(encrypted)

        def send_list (self, filename_string, seqA, seqB):
            '''
            Send a encrypted string of list of files presesnt in server to client
            returns seqA, seqB
            '''
            chunk_size = 30
            key_string = "Bob".encode()+self.k1
            offset = 0
            end_loop = False
            while not end_loop:
                #The chunk
                chunk = filename_string[offset:offset + chunk_size]
                trial_count = 2
                while trial_count > 0 and trial_count < 2:
                    #If the data chunk is less then the chunk size, then we need to add
                    #padding with " ". This indicates the we reached the end of the file
                    #so we end loop here
                    if len(chunk) % chunk_size != 0:
                        end_loop = True
                        chunk += pad(chunk,chunk_size - len(chunk))

                    chunk = self.int_to_bytes(len(chunk),2) + chunk
                    # Encryption using SHA
                    msg = self.get_encrypted_msg_with_integrity(chunk,key_string+self.int_to_bytes(seqA,32))
                    self.socket.send(msg)

                    # TODO: receive message from server anc check for integrity
                    recv_msg = self.socket.recv(64)
                    msg = self.get_decrypted_msg(recv_msg,"Alice".encode()+self.k1+self.int_to_bytes(seqA,32))
                    ack_length = msg[0:2]
                    ack_chunk = msg[2:ack_length]
                    if ack_chunk != "Ok".encode():
                        trial_count -= 1
                    #Increase the offset by chunk size
                    seqA += 1
                    seqB += 1
                

                if trial_count == 0:
                    end_loop = True
                offset += chunk_size

            self.send_command("End",seqA,seqB)
            return seqA,seqB


        



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
            traceback.print_exc()
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
