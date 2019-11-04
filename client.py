import socket
import sys

s = socket.socket()
s.connect(("localhost",5543))
print("Connection established")
f = open ("./input_directory/izuku2.jpg", "rb")
s.send('izuku2.jpg'.encode('utf-8'))
l = f.read(1024)
while (l):
    s.send(l)
    l = f.read(1024)
s.close()