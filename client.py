import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import zlib
import uuid
import random 
import traceback

class Client:

    def __init__(self):
        self.socket = ''

    def set_keys(self,k1,k2,k3,k4):
        self.k1 = k1
        self.k2 = k2
        self.k3 = k3
        self.k4 = k4
        self.command_list = ["Upload","Download","List","End","Close"]

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
        print("Na ",Na.bytes)
        initial_conn_string = rsa_key.encrypt(Na.bytes+"Alice".encode())
        # print(initial_conn_string)

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
        print("Nb recv ",Nb)
        session_key = strxor(Na.bytes,Nb)

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
        return data.to_bytes(32,byteorder='big')[-length:]

    def initiate_connection(self):
        """
        Initiates socket connection

        Returns:

         - s: socket
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        seqA_bytes = get_random_bytes(32)
        seqA = int.from_bytes(seqA_bytes, byteorder='big')
        print("seqA : ",seqA)
        key_string = "Alice".encode()+self.k1
        #send the message and hash of message(32 bytes each)
        msg = self.get_encrypted_msg_with_integrity(seqA_bytes,key_string)
        self.socket.send(msg)
        return seqA
    
    def recv_seqB(self):
        '''
        Calculates the server side initial seq number 
        returns the server seq number as int
        '''
        msg = self.socket.recv(64)
        sha_integrity_key_string = "Bob".encode()+self.k1
        seqB_bytes = self.get_decrypted_msg(msg,sha_integrity_key_string)
        seqB = int.from_bytes(seqB_bytes, byteorder='big')
        #verified till previous line ; we got back seq number
        return seqB

       
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
        
    def send_command(self,command,seqA,seqB,path=""):
        arr = path.split("/")
        file_name = arr[len(arr)-1]
        command_chunk = (command+file_name).encode()
        command_chunk = self.int_to_bytes(len(command_chunk),2) + command_chunk
        msg = self.get_encrypted_msg_with_integrity(command_chunk,"Alice".encode()+self.k1+self.int_to_bytes(seqA,32))
        self.socket.send(msg)
        recv_msg = self.socket.recv(64)
        msg = self.get_decrypted_msg(recv_msg,"Bob".encode()+self.k1+self.int_to_bytes(seqB,32))
        ack_length = self.bytes_to_int(msg[0:2])
        ack_chunk = msg[2:2+ack_length]
        if "Ok".encode() != ack_chunk:
            print("Ack_Chunk: ", ack_chunk)
            raise Exception("Command not received")


    def send_file(self,path,seqA, seqB):
        # TODO: File transfer gets corrupted and the file retransmission is required in the middle of 
        # exchange
        self.send_command("Upload,",seqA,seqB,path)
        seqA += 1
        seqB += 1
        f_file = open(path, 'rb')
        file_data= f_file.read()
        f_file.close()
        #compress the data first
        # file_data = zlib.compress(file_data)
        #will encrypt and decrypt chunks at a time
        chunk_size = 30
        key_string = "Alice".encode()+self.k1
        offset = 0
        end_loop = False

        while not end_loop:
            #The chunk
            chunk = file_data[offset:offset + chunk_size]
            trial_count = 2
            while trial_count > 0 and trial_count <= 2:
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
                msg = self.get_decrypted_msg(recv_msg,"Bob".encode()+self.k1+self.int_to_bytes(seqB,32))
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

    def receive_file(self):
        pass
    
def user_interface ():
    #display list of files and ask for upload or download 
    #return command, filename
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
        print("session: ", session)
        k1 = client.int_to_bytes(session + 2)
        k2 = client.int_to_bytes(session + 5)
        k3 = client.int_to_bytes(session + 7)
        k4 = client.int_to_bytes(session + 9)
        client.set_keys(k1,k2,k3,k4)
        exit_flag = False
        while not exit_flag:
            # TODO: Step 3 and 4 inside send_file and different sequence numbers for each file
                    #send 3rd message

            # Exchange sequence numbers before every command
            seqA = client.send_seqA_num()
            #receive 4th message
            seqB = client.recv_seqB()
            path = 'client_directory/izuku.jpg'
            seqA,seqB = client.send_file(path,seqA+1,seqB+1)
            exit_flag = input("Continue?") == "False"
    except Exception as e:
        print(str(e))
        traceback.print_exc()
    finally:
        client.close_connection()

# print('Encrypting file...')
# rsa_key = RSA.importKey(public_key)
# initial_string = rsa_key.encrypt(Na+"Alice")
# f_file = open('client_directory/izuku.jpg', 'rb')
# data= f_file.read()
# f_file.close()
# encrypted_data = encrypt_file(public_key, data)
# fd = open("encrypted_img.jpg", "wb")
# fd.write(encrypted_data)
# fd.close()

# f = open("/home/rik/netsec/Secure-File-Transfer-Application/client_directory/izuku.jpg", "rb")
# # s.send('encrypted_img.jpg'.encode('utf-8'))
# l = f.read(1024)
# while (l):
#     s.send(l)
#     l = f.read(1024)
# # s.close()
