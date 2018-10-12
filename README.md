# Crypto-Hw2
### Cryptography and Network Security Hw2

This program builds upon my work from homework one where a file is transfered over tcp using a toy des encryption method.  
In the original implementation of my toy des requires the session key between the two parties to be entered by the users 
on each end, in order to ensure that they have the same key.  This project builds on top of that and uses the Needham-Schroeder
Protocol to distribute the session key to both parties.

The file kdc.py is a server that acts as the Key Distribution Center for the NS implementation.  The file file_transfer.py
is run from two different locations, and act as the two parties looking to communicate securely.  In order for NS to work,
the KDC must know the secret keys for both parties.  So, upon startup of file_transfer.py, it will immediately look to 
connect to the KDC to generate a secret key that only it and the KDC know.  This implementation uses Diffie-Hellman to 
compute the secret keys.  After the secret keys have been set up with the KDC, the program will then look to connect
to the other party, get the session key using NS, and finally encrypt and send the file using the toy des implementation.

## How to Run
This program was implemented using **Python 3**.
1. Start up the KDC server kdc.py
	+ The port it is listening on will be printed
2. Run file_transfer.py from two different locations (One for Alice one for Bob)
3. Enter the id for each user, this should only be one character (ex. A for Alice and B for Bob)
3. The first series of prompts will ask for information to connect to the KDC
	1. IP address for KDC
	2. Port for KDC
4. After this information is in, it will connect to the KDC and compute their secret keys using Diffie-Hellman
5. The next steps are very similar to my homework 1 implementation. The program will ask if this user is the sender
or receipient (SEND or RECEIVE).
	+ On the RECEIVE end, it will now just listen for a connection from the sender, and it prints the port it is listening on.
	+ On the SEND end, it will ask a series of prompts about the sender and which file to send.
		1. File to send
		2. Recipient ID
		3. Recepient IP
		4. Recipient Port
6. After all the information is gathered, the sender will connect to both the KDC and the receiver and get the session key.
It will then encrypt the file using the session key and toy des, and send it.  Finally the recipient will then receive and decrypt the
file.

## Implementation Details

### Diffie-Hellman
My Diffie-Hellman implementation makes a couple key assumptions for it to work well with my existing toy-des. Since the toy-des
expects a 10-bit key, I made sure to cap my global prime Q at 1021, as it is the largest prime we can get with only 10 bits. This obviously 
is not super secure, but the point of this assignment is more educational than practical.  Q, along with ALPHA, are defined globally in
both kdc.py and file_transfer.py. The client initiates the connection by sending its ID, and, after receiving an aknowledgement, it will
send a packet with "DH", to let the server know that it wants to compute a key with Diffie-Hellman. The client and server both pick a secret 
key, s < Q, and compute ALPHA^s mod Q. This result is shared with eachother, and can compute the shared key by raising that result to s, 
and again taking mod Q.  The server will then store the shared key in a dictionary and correspond it with the user's ID.

### Needham-Schroeder
The sender initiates the connection by sending its ID, and, after receiving an aknowledgement, it will send a packet with "NS", to let the 
server know that it wants to compute a key with NS.  The server will pick a key and give it to the sender, who will then share it with the
receiver.  This transaction is done in the following steps:
1. A->KDC: ID<sub>A</sub> \|\| ID<sub>B</sub> \|\| N<sub>1</sub>
2. KDC->A: E<sub>K<sub>A</sub></sub>[K<sub>s</sub>]