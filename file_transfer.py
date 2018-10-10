import sys
import socket
import random
import toy_des as des

Q = 1021
ALPHA = 999

#convert bytes to a string of bits
def getBits(byte):
	hexi = byte.hex()
	binary = bin(int(hexi, 16))[2:]
	#add leading 0s
	while len(binary) < len(byte)*8:
		binary = "0" + binary
	return binary

#convert a string of bits to bytes
def getBytes(binary):
	hexi = hex(int("0b"+binary, 2))[2:]
	#add leading 0s
	while len(hexi) < len(binary)/4:
		hexi = "0" + hexi
	return bytes.fromhex(hexi)

#returns true if key is valid, false otherwise
def checkKey(key):
	#check length
	if len(key) != 10:
		return False
	#check that it's binary
	for b in key:
		if b != "0" and b != "1":
			return False
	return True 

#read user input and set up connections
def getCommand():
	#Prompt for key
	key = input("10-bit Key: ")
	if not checkKey(key):
		print("invalid key")
		return
	#Prompt for command
	command = input("SEND or RECEIVE? ")

	if command == "RECEIVE":
		#listen for connections
		port = int(random.random()*64511 + 1024)
		sock.bind(("", socket.htons(port)))
		sock.listen(1)
		print("Listening for connections on", port)
		recvFile(key)

	elif command == "SEND":
		#get the file
		filename = input("file: ")
		try:
			file = open(filename, "rb")
		except:
			print ("Could not open file:", filename)
			return

		#Get address of destination
		ip = input("IP: ")
		port = int(input("Port: "))

		#attempt to connect
		try:
			sock.connect((ip, socket.htons(port)))
		except:
			print("Unable to connect")
			return
		#send the file
		sendFile(file, key)

	else:
		print("Invalid Command")
		return

#Ecrypts and sends the file
def sendFile(file, key):
	#Send name of file first
	cypher = des.encrypt(getBits(bytes(file.name, "utf-8")), key)
	sock.sendall(getBytes(cypher))

	#Wait for acknowledgement 
	ack = sock.recv(1024)
	if ack != b'ACK': 
		sendFile(file, key)
		return

	#Send the rest
	data = file.read(1024)
	while len(data) != 0:
		#ENCRYPT
		cypher = des.encrypt(getBits(data), key)
		sock.sendall(getBytes(cypher))
		data = file.read(1024)
	file.close()
	print("Complete")

#listens on a port for a connection
#receives a file, decrypts and saves.
def recvFile(key):
	#wait for connection
	fd, addr = sock.accept()
	print("Conncetion received from", addr)

	#receive first packet (filename)
	cypher = fd.recv(1024)
	#DECRYPT
	filename = getBytes(des.decrypt(getBits(cypher), key))
	#open the file
	file = open(filename, "wb")

	#Send Acknowledgement
	fd.sendall(b'ACK')

	cypher = fd.recv(1024)
	while len(cypher) != 0:
		#DECRYPT
		data = des.decrypt(getBits(cypher), key)
		file.write(getBytes(data))
		cypher = fd.recv(1024)

	fd.close()
	print("Received file:", filename.decode())


###MAIN###
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
getCommand()
sock.close()
