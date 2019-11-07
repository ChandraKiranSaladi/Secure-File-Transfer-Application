import socket
import sys
from Crypto.PublicKey import RSA
import zlib
import base64
from Crypto.Cipher import PKCS1_OAEP
'''
Generate RSA public/private key of server
'''
def generate_key():
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

def encrypt_file(public_key, file_data):
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
    return base64.b64encode(encrypted)

s = socket.socket()
s.bind(("localhost",5543))
s.listen(10)
generate_key()
while True:
    sock, address = s.accept()

    print("Connection accepted from ",address)

    #File Name
    file_name = sock.recv(1024).decode('utf-8')
    print('file received with file_name')
    print(file_name)

    f= open("/home/rik/netsec/Secure-File-Transfer-Application/output_directory/"+file_name,'wb')
    l = 1
    while (l):       
        # receive data and write it to file
        l =  sock.recv(1024)
        while (l):
                f.write(l)
                l =  sock.recv(1024)
        print("I'm Done Here ")

        
                
        

s.close()
