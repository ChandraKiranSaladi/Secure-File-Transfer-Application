import socket
import datetime
import os
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
            
            - data: Data in bytes

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

            - data: int
            - length: length of bytes needed ( max 32 )

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


    def send_seqA_receive_seqB(self):
        """
        Generates seqA: random number and sends it to server
        as encrypted message and decrypts seqB sent by server

        Returns:
            - seqA : 32 byte integer
            - seqB : 32 byte integer
        """
        seqA_bytes = get_random_bytes(32)
        seqA = int.from_bytes(seqA_bytes, byteorder='big')
        print("sending seqA : ",seqA)
        sha_key_string = "Alice".encode()+self.k1
        sha_integrity_key_string = self.k2
        #send the message and hash of message(32 bytes each)
        msg = self.get_encrypted_msg_with_integrity(seqA_bytes,sha_key_string, sha_integrity_key_string)
        self.socket.send(msg)
        msg = self.socket.recv(64)
        sha_key_string = "Bob".encode()+self.k1
        seqB_bytes = self.get_decrypted_msg(msg,sha_key_string,sha_integrity_key_string)
        seqB = int.from_bytes(seqB_bytes, byteorder='big')
        print("seqB recv", seqB)
        #verified till previous line ; we got back seq number
        return seqA,seqB
    
      
    def close_connection(self):
        self.socket.close()


    def get_encrypted_msg_with_integrity(self,msg,sha_key_string,sha_integrity_key_string):
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


    def get_decrypted_msg(self,msg,sha_key_string,sha_integrity_key_string):
        """
            Checks integrity and decrypts message

            - msg: 64 byte payload ( 32 byte message + 32 byte integrity)
            - sha_key_string : key in bytes

            Returns:
                - bytes : Decrypted message in bytes 
        """
        integrity = msg[32:]
        msg = msg[:32]
        decrypted_msg = strxor(SHA256.new(sha_key_string).digest(),msg)

        sha_integrity = SHA256.new(decrypted_msg+sha_integrity_key_string).digest()

        if  not sha_integrity == integrity:
            print("Message is tampered")
            raise ValueError('message is tampered')

        return decrypted_msg
        

    def send_command(self,command,seqA,seqB,encryption_key,integrity_key,path=""):
        """
            Sends command to the Server and waits for acknowledgement

            - command: str
            - seqA : int
            - seqB : int
            - encryption_key : key for encryption
            - decryption_key : key for decryption

        """
        arr = path.split("/")
        file_name = arr[len(arr)-1]
        command_chunk = (command+file_name).encode()
        command_chunk = self.int_to_bytes(len(command_chunk),2) + command_chunk
        msg = self.get_encrypted_msg_with_integrity(command_chunk,"Alice".encode()+encryption_key+self.int_to_bytes(seqA,32),integrity_key+self.int_to_bytes(seqA,32))
        self.socket.send(msg)
        if command == "Ok":
            return
        recv_msg = self.socket.recv(64)
        msg = self.get_decrypted_msg(recv_msg,"Bob".encode()+encryption_key+self.int_to_bytes(seqB,32),integrity_key+self.int_to_bytes(seqB,32))
        ack_length = self.bytes_to_int(msg[0:2])
        ack_chunk = msg[2:2+ack_length]
        if "Ok".encode() != ack_chunk:
            print("Ack_Chunk: ", ack_chunk)
            print("Command not received")
            raise Exception("Command not received")


    def send_data(self,data,seqA, seqB, encryption_key, integrity_key):
        """
            Sends data to server in encrypted channel

            - data: bytes 
            - seqA: int 
            - seqB: int
            - encryption_key : key for encryption
            - decryption_key : key for decryption

        """

        # TODO: File transfer gets corrupted and the file retransmission is required in the middle of 
        # exchange
        #compress the data first
        # file_data = zlib.compress(file_data)
        #will encrypt and decrypt chunks at a time
        chunk_size = 30
        key_string = "Alice".encode()+encryption_key
        offset = 0
        end_loop = False
        print("File length: ",len(data))
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
                msg = self.get_encrypted_msg_with_integrity(chunk,key_string+self.int_to_bytes(seqA,32), integrity_key+self.int_to_bytes(seqA,32))
                self.socket.send(msg)
                
                recv_msg = self.socket.recv(64)
                msg = self.get_decrypted_msg(recv_msg,"Bob".encode()+encryption_key+self.int_to_bytes(seqB,32),integrity_key+self.int_to_bytes(seqB,32))
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
        
        self.send_command("End,",seqA,seqB, encryption_key, integrity_key)
        # return seqA,seqB
        #Base 64 encode the encrypted file
        # return base64.b64encode(encrypted)


    def receive_data(self,seqA,seqB, encryption_key, integrity_key):
        """
            Receives data from Server in encrypted channel

            - seqA : int
            - seqB : int
            - encryption_key : key for encryption
            - decryption_key : key for decryption

            Returns:
                - data -> bytes 

        """
        
        data = b''
        count = 0
        start_time = datetime.datetime.now()
        while True:
            msg = self.get_decrypted_msg(self.socket.recv(64),"Bob".encode()+encryption_key+self.int_to_bytes(seqB,32), integrity_key+self.int_to_bytes(seqB,32))
            chunk_length = self.bytes_to_int(msg[0:2])
            chunk = msg[2:2+chunk_length]
            if count%100000 == 0:
                print("Time taken for {} is {}".format(count*32,datetime.datetime.now()-start_time))
            try:
                if chunk[0:3].decode() == "End":
                    self.send_command("Ok",seqA,seqB, encryption_key, integrity_key)
                    seqA += 1
                    seqB += 1
                    break
            except UnicodeDecodeError:
                pass
            self.send_command("Ok",seqA,seqB, encryption_key, integrity_key)
            data += chunk
            seqA += 1
            seqB += 1
            count += 1
        return data
    

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
        server_file_list = []
        
        while True:
            print('Please choose an option: ')
            print('1. List all server files')
            print('2. List all client files')
            print('3. Upload')
            print('4. Download')
            print('5. Exit')
            choice = int(input('Enter your choice :'))

            if choice == 1:
                seqA, seqB = client.send_seqA_receive_seqB()
                client.send_command("List,",seqA+1,seqB+1, k1, k2)
                filename_string = client.receive_data(seqA+2,seqB+2, k1,k2).decode()
                server_file_list =  filename_string.split(';')
                print('Listing server file names: ')
                print(server_file_list)
                
            elif choice == 2:
                for file_name in os.listdir('./client_directory'):
                    print(file_name)

            elif choice == 3:
                path = "./client_directory/"+input('Enter File Name :')
                if not os.path.isfile(path):
                    print('File not found')
                else:
                    seqA, seqB = client.send_seqA_receive_seqB()
                    client.send_command("Upload,",seqA+1,seqB+1,k1, k2, path)
                    f_file = open(path, 'rb')
                    data = f_file.read()
                    start_time = datetime.datetime.now()
                    client.send_data(data,seqA+2,seqB+2, k1, k2)
                    print("Time taken for {} is {}".format(len(data),datetime.datetime.now()-start_time))

            elif choice == 4:
                download_filename = input ('Enter file name ')
                if download_filename not in server_file_list:
                    print('FIle not found in Server')
                else:
                    seqA, seqB = client.send_seqA_receive_seqB()
                    client.send_command("Download,",seqA+1,seqB+1, k1, k2,download_filename)
                    #using k3 and k4 for download 
                    start_time = datetime.datetime.now()
                    file_data = client.receive_data(seqA+2,seqB+2, k3, k4)
                    print("Time taken for {} is {}".format(len(file_data),datetime.datetime.now()-start_time))
                    f = open('./client_directory/'+download_filename,'wb')
                    f.write(file_data)
                    f.close()

            elif choice == 5:
                print("Exiting Application")
                break
            else:
                print("Choose valid options bruh")

    except Exception as e:
        print("Exception occured closing Socket connection")
        # print(str(e))
        # traceback.print_exc()
    finally:
        client.close_connection()
