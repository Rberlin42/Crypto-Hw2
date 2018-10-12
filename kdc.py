import sys
import socket
import _thread as thread
import random
import toy_des as des

#Shared global parameters for Diffie-Hellman
#capped at 1021 to be compatable with 10-bit key required for toy_des
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

#Function for threads to handle connections
def handle_connection(fd, addr):
	print("Received connection from", addr)

	#get id of client
	cli_id = fd.recv(1).decode()
	fd.sendall(b"ACK")

	#get the command sent and check if it's valid
	# DF for diffie-hellman
	# GETKEY to get a session key
	command = fd.recv(2)
	if command == b"DH":
		fd.sendall(b"ACK")
		diffieHellman(fd, cli_id)
	elif command == b"NS":
		fd.sendall(b"ACK")
		NS(fd, cli_id)
	else:
		fd.sendall(b"ERROR: Invalid Command")
	fd.close()

#Creates a key for the connected client using diffie-hellman
def diffieHellman(fd, cli_id):
	print("Computing diffie-hellman with", cli_id)

	#generate our public key
	secret = int(random.random()*Q)
	public  = (ALPHA**secret) % Q

	#receive client's public key and send ours
	client_public = int(fd.recv(4))
	fd.sendall(str(public).encode())

	#calculate the session key
	session_key = (client_public**secret) % Q

	#store the key for this client
	users[cli_id] = session_key

	print("Secret key for", cli_id, "is", session_key)

#Send the client an encryped session key according to the NS protocol
def NS(fd, cli_id):
	#Receive and parse first packet
	packet = fd.recv(4)
	if cli_id != packet[:1].decode():
		print("Error: incorrect id")
		exit()
	cli_id2 = packet[1:2].decode()
	N1 = int.from_bytes(packet[2:], byteorder="big")

	print("Generating session key for", cli_id, "and", cli_id2)

	#randomly generate session key
	session_key = int(random.random()*Q)
	print("Key is", session_key)

	#git bit forms of secret keys
	Ka = getBits(users[cli_id].to_bytes(2, byteorder="big"), 10)
	Kb = getBits(users[cli_id2].to_bytes(2, byteorder="big"), 10)

	#create and encrypt string to send back
	str1 = getBits(session_key.to_bytes(2, byteorder="big") + cli_id.encode())
	encryped_str1 = des.encrypt(str1, Kb)
	str2 = getBits(session_key.to_bytes(2, byteorder="big") + cli_id2.encode() + N1.to_bytes(2, byteorder="big")) + encryped_str1
	encrypted_str2 = des.encrypt(str2, Ka)

	#Send key back to client
	fd.sendall(getBytes(encrypted_str2, 8))
	


###MAIN###

#dictionary to store secret keys for users
users = {}
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = int(random.random()*64511 + 1024)
sock.bind(("", socket.htons(port)))
sock.listen(1)
print("Listening for connections on", port)

while True:
	client = sock.accept()
	thread.start_new_thread(handle_connection, client)

