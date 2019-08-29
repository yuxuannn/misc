#!/usr/bin/env python3

import http.client

print("Returns a list of methods if OPTIONS flag is enabled")
host = input("Enter target host/IP: ")
port = input("Enter target port: ")


#class http.client.HTTPConnection(host, port=None, [timeout, ]source_address=None, blocksize=8192)
try:
	connection = http.client.HTTPConnection(host, port)
	connection.request("OPTIONS", "/")
	response = connection.getresponse()
	response.read()						#required or ResponseNotReady
	print("Enabled methods are: ", response.getheader("allow"))

	connection.request("GET" , "/")
	response = connection.getresponse()
	print("Status of GET: ", response.status, response.reason)
	response.read()						#required or ResponseNotReady	

	connection.close()

except ConnectionRefusedError:
	print("Connection Failed")
	connection.close()
