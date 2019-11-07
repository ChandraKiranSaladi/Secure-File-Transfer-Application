import socket
import sys
import socket
import sys
from Crypto.PublicKey import RSA
import zlib
import base64
from Crypto.Cipher import PKCS1_OAEP

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
s.connect(("localhost",5543))
print("Connection established")
print('Encrypting file...')
f_pubk = open('public_key.pem', 'rb')
public_key = f_pubk.read()
f_pubk.close()
f_file = open('input_directory/izuku.jpg', 'rb')
data= f_file.read()
f_file.close()
encrypted_data = encrypt_file(public_key, data)
fd = open("encrypted_img.jpg", "wb")
fd.write(encrypted_data)
fd.close()

f = open ("/home/rik/netsec/Secure-File-Transfer-Application/input_directory/izuku.jpg", "rb")
s.send('encrypted_img.jpg'.encode('utf-8'))
l = f.read(1024)
while (l):
    s.send(l)
    l = f.read(1024)
s.close()
