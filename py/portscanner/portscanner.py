#!/usr/bin/env python3

import socket

portstart = int(input("Input starting port no: "))
portend = int(input("Input ending port no: "))
TAR_ADDR = input("Input target IP address: ")

for i in range(portstart, portend):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	if(s.connect_ex((TAR_ADDR, i))):
		print("Port ", i ," is closed")
	else:
		print("Port ", i ," is open")
	s.close()
