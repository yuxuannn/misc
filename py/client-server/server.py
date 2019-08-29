#!/usr/bin/env python3

import socket
import sys

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
conn, addr = s.accept()

print('Connected by', addr)
while True:
	data = input("> ")
	conn.send(data.encode())
	if data == 'exit':
		break
	print(conn.recv(1024))

s.close()

