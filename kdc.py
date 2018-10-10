import sys
import socket
import thread
import random
import toy_des as des

#Shared global parameters for Diffie-Hellman
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

#Function for threads to handle connections
def handle_connection(client):
	fd, addr = client
	print("Received connection from", addr)

	#get id of client
	cli_id = fd.recv(1)
	fd.send("ACK")

	#get the command sent and check if it's valid
	# DF for diffie-hellman
	# GETKEY to get a session key
	command = fd.recv(6)
	if command == "DF":
		diffieHellman(fd, addr, cli_id)
	elif command == "GETKEY":
		createSessionKey(fd, addr, cli_id)
	else:
		fd.send("ERROR: Invalid Command")
	fd.close()

def diffieHellman(fd, cli_id):
	print("Computing diffie-hellman with", cli_id)

	#generate our public key
	secret = int(random.random()*Q)
	public  = (ALPHA**secret) % Q

	#receive client's public key and send ours
	client_public = int(fd.recv(4))
	fd.send(public)

	#calculate the session key
	session_key = (client_public**secret) % Q

	#store the key for this client
	users[cli_id] = sesson_key

	print("Secret key for", cli_id, "is", sesson_key)


	


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

