import socket
import sys

s = socket.socket()
s.bind(("localhost",5543))
s.listen(10)

while True:
    sock, address = s.accept()

    print("Connection accepted from ",address)

    #File Name
    file_name = sock.recv(1024).decode('utf-8')

    f= open("./output_directory/"+file_name,'wb')
    l = 1
    while (l):       
        # receive data and write it to file
        l =  sock.recv(1024)
        while (l):
                f.write(l)
                l =  sock.recv(1024)
        print("I'm Done Here ")
        f.close()
        sock.close()

s.close()
