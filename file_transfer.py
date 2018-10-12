import sys
import socket
import random
import toy_des as des

#Shared global parameters for Diffie-Hellman
Q = 1021
ALPHA = 999

#convert bytes to a string of bits
def getBits(byte, length=None):
	hexi = byte.hex()
	binary = bin(int(hexi, 16))[2:]
	#add leading 0s
	if length == None: length = len(byte) * 8
	while len(binary) < length:
		binary = "0" + binary
	return binary[:length]

#convert a string of bits to bytes
def getBytes(binary, length=None):
	hexi = hex(int("0b"+binary, 2))[2:]
	if len(hexi) % 2 == 1: hexi = "0" + hexi
	byte = bytes.fromhex(hexi)
	#add leading 0s
	if length == None: length = len(binary) // 4
	while len(byte) < length:
		byte = bytes.fromhex("00") + byte
	return byte[:length]

#convert bytes to a string of bits
def getBit(byte):
	hexi = byte.hex()
	binary = bin(int(hexi, 16))[2:]
	#add leading 0s
	while len(binary) < len(byte)*8:
		binary = "0" + binary
	return binary

#convert a string of bits to bytes
def getByte(binary):
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

	#Prompt for command
	command = input("SEND or RECEIVE? ")

	if command == "RECEIVE":
		#listen for connections
		port = int(random.random()*64511 + 1024)
		sock.bind(("", socket.htons(port)))
		sock.listen(1)
		print("Listening for connections on", port)
		#wait for connection
		fd, addr = sock.accept()
		print("Conncetion received from", addr)

		###GET SESSION KEY WITH NS***
		key = NS_receiver(fd)
		recvFile(key, fd)

	elif command == "SEND":
		#get the file
		filename = input("file: ")
		try:
			file = open(filename, "rb")
		except:
			print ("Could not open file:", filename)
			return

		#Get address of destination
		id_b = input("ID of recipient: ")
		ip = input("IP: ")
		port = int(input("Port: "))

		#attempt to connect
		try:
			sock.connect((ip, socket.htons(port)))
		except:
			print("Unable to connect")
			return

		###GET SESSION KEY WITH NS***
		key = NS_sender(id_b)
		#send the file
		sendFile(file, key)

	else:
		print("Invalid Command")
		return

#NS protocol for the first user
#returns the session key
def NS_sender(recipient_id):
	#Create a new socket to talk with the KDC
	kdc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	kdc_sock.connect((kdc_ip, socket.htons(kdc_port)))

	#initiate NS with the server
	kdc_sock.sendall(ID.encode())
	ack = kdc_sock.recv(64)
	if ack != b"ACK":
		print(ack)
		exit()
	kdc_sock.sendall(b"NS")
	ack = kdc_sock.recv(64)
	if ack != b"ACK":
		print(ack)
		exit()

	#Pick a nonce and send string to kdc
	N1 = int(random.random()*Q)
	s = ID.encode() + recipient_id.encode() + N1.to_bytes(2, byteorder="big")
	kdc_sock.sendall(s)

	#receive the encrypted string and decrypt it
	packet = getBytes(des.decrypt(getBits(kdc_sock.recv(8)), secret_key), 8)
	#first 2 bytes will be session key
	session_key = getBits(packet[:2], 10)
	print("Session key is", int.from_bytes(packet[:2], byteorder="big"))
	#check the the returned id is correct
	if packet[2:3].decode() != recipient_id:
		print("Error: incorrect id", packet)
		exit()
	#check that the Nonce is correct
	if int.from_bytes(packet[3:5], byteorder="big") != N1:
		print("Error: incorrect nonce")
		exit()

	#end communication with kdc server
	kdc_sock.close()

	#Send ecrypted session key to receipient
	sock.sendall(packet[5:8])
	#Receive the nonce encrypted with the new session key
	N2_bits = des.decrypt(getBits(sock.recv(2)), session_key)
	N2 = int.from_bytes(getBytes(N2_bits, 2), byteorder="big")
	#perform a simple function on the nonce and send it back encrypted
	N2 -= 1
	encrypted_N2 = des.encrypt(getBits(N2.to_bytes(2, byteorder="big")), session_key)
	sock.sendall(getBytes(encrypted_N2, 2))

	#receive the acknowledgement from the receipient that the key works
	ack = sock.recv(8)
	if ack != b"ACK":
		print("NS failed")
		exit()

	return session_key



#NS protocol for the second user
#returns the session key
def NS_receiver(fd):
	#Receive session key from sender
	keystring = getBytes(des.decrypt(getBits(fd.recv(3)), secret_key), 3)
	session_key = getBits(keystring[:2], 10)
	print("Session key is", int.from_bytes(keystring[:2], byteorder="big"), "for sender", keystring[2:3].decode())

	#pick a nonce and send it encrypted with the new key
	N = int(random.random()*Q)
	encrypted_N = des.encrypt(getBits(N.to_bytes(2, byteorder="big")), session_key)
	fd.sendall(getBytes(encrypted_N, 2))

	#Receive the altered nonce, decrypt it, and make sure that it's correct
	N2 = int.from_bytes(getBytes(des.decrypt(getBits(fd.recv(2)), session_key), 2), byteorder="big")
	if N2 == N - 1:
		fd.sendall(b"ACK")
	else:
		fd.sendall(b"ERROR")
		print("Error: incorrect nonce")
		exit()

	return session_key


#Ecrypts and sends the file
def sendFile(file, key):
	#Send name of file first
	cypher = des.encrypt(getBit(bytes(file.name, "utf-8")), key)
	sock.sendall(getByte(cypher))

	#Wait for acknowledgement 
	ack = sock.recv(1024)
	if ack != b'ACK': 
		sendFile(file, key)
		return

	#Send the rest
	data = file.read(1024)
	while len(data) != 0:
		#ENCRYPT
		cypher = des.encrypt(getBit(data), key)
		sock.sendall(getByte(cypher))
		data = file.read(1024)
	file.close()
	print("Complete")

#listens on a port for a connection
#receives a file, decrypts and saves.
def recvFile(key, fd):

	#receive first packet (filename)
	cypher = fd.recv(1024)
	#DECRYPT
	filename = getByte(des.decrypt(getBit(cypher), key))
	#open the file
	file = open(filename, "wb")

	#Send Acknowledgement
	fd.sendall(b'ACK')

	cypher = fd.recv(1024)
	while len(cypher) != 0:
		#DECRYPT
		data = des.decrypt(getBit(cypher), key)
		file.write(getByte(data))
		cypher = fd.recv(1024)

	fd.close()
	print("Received file:", filename.decode())

#Computes the secret key with the KDC using diffie-hellman
def diffieHellman():
	#Initiate diffie Hellman with server
	sock.sendall(ID.encode())
	ack = sock.recv(64)
	if ack != b"ACK":
		print(ack)
		exit()
	sock.sendall(b"DH")
	ack = sock.recv(64)
	if ack != b"ACK":
		print(ack)
		exit()

	#generate our public key
	secret = int(random.random()*Q)
	public  = (ALPHA**secret) % Q

	#receive kdc's public key and send ours
	sock.sendall(str(public).encode())
	kdc_public = int(sock.recv(4))

	#calculate the session key
	session_key = (kdc_public**secret) % Q

	print("Secret key is", session_key)
	return session_key

###MAIN###
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#get ID from user
ID = input("Enter ID: ")
if len(ID) > 1:
	print("ID must have length 1")
	exit()

#Compute secret key with KDC
#get ip and port of kdc
kdc_ip = input("Enter KDC IP: ")
kdc_port = int(input("Enter KDC Port: "))
sock.connect((kdc_ip, socket.htons(kdc_port)))
secret_key = getBits(diffieHellman().to_bytes(2, byteorder="big"), 10)
sock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
getCommand()
sock.close()
