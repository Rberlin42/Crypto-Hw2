#permutations
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
Pinital = [2, 6, 3, 1, 4, 8, 5, 7]
Pinverse = [4, 1, 3, 5, 7, 2, 8, 6]
P10to8 = [6, 3, 7, 4, 8, 5, 10, 9]
P4expansion = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

#S-Boxes
S0 = [["01", "00", "11", "10"],
	  ["11", "10", "01", "00"],
	  ["00", "10", "01", "11"],
	  ["11", "01", "11", "10"]]
S1 = [["00", "01", "10", "11"],
	  ["10", "00", "01", "11"],
	  ["11", "00", "01", "00"],
	  ["10", "00", "01", "11"]]


#returns a permutation of the bits according to the array permutation
def permuteBits(bits, permutation):
	newString = ""
	for p in permutation:
		newString += bits[p-1]
	return newString


#takes 4-bit input and returns 2-bits based on the sbox
def substituteBits(bits, sbox):
	#check length
	if len(bits) != 4:
		raise ValueError("Must enter 4 bits")

	#calculate row using first and last bits
	row = int("0b" + bits[0] + bits[3], 2)
	#calculate col using middle bits
	col = int("0b" + bits[1] + bits[2], 2)

	return sbox[row][col]


#Shifts the bits by amount
#positive amount is left shift, negative is right
def shiftBits(bits, amount):
	shifted = ""
	for i in range(len(bits)):
		i = (i + amount) % len(bits)
		shifted += bits[i]
	return shifted


#takes 10-bit key and returns 8-bit keys (k1, k2)
def getSubKeys(key):
	#Permute
	key = permuteBits(key, P10)
	#split in half
	left = key[:5]
	right = key[5:]
	#left shift each
	left = shiftBits(left, 1)
	right = shiftBits(right, 1)

	#Combine, permute and get k1
	k1 = left + right
	k1 = permuteBits(k1, P10to8)

	#shift again, combine, permute and get k2
	left = shiftBits(left, 1)
	right = shiftBits(right, 1)
	k2 = left + right
	k2 = permuteBits(k2, P10to8)

	return k1, k2


#computes the xor of two binary strings
#must be same length
def XOR(b1, b2):
	#check length
	if len(b1) != len(b2):
		raise ValueError("bit strings must be same length")

	#compute the xor
	xor = int("0b" + b1, 2) ^ int("0b" + b2, 2)

	#convert back to binary
	result = bin(xor)
	#remove "0b"
	result = result[2:]
	#add leading 0s
	while len(result) < len(b1):
		result = "0" + result

	return result


#F function
#must be 4-bit input and 8-bit key
def F(bits, key):
	#check lengths of inputs
	if len(bits) != 4:
		raise ValueError("must be 4-bit input")
	if len(key) != 8: 
		raise ValueError("must be 8-bit key")

	#expand/permute bits
	bits = permuteBits(bits, P4expansion)
	#xor with key
	bits = XOR(bits, key)
	#split in half
	left = bits[:4]
	right = bits[4:]
	#put them through the Sboxes
	left = substituteBits(left, S0)
	right = substituteBits(right, S1)

	#combine them back and permute
	return permuteBits(left+right, P4)


#DES encrytion or decryption on an 8-bit block of data
#direction is either "ENCRYPT" or "DECRYPT"
def toy_des(data, key, direction):
	#check length of data
	if len(data) != 8:
		raise ValueError("block must be 8 bits")

	#create subkeys from key
	if direction == "ENCRYPT":
		k1, k2 = getSubKeys(key)
	elif direction == "DECRYPT":
		k2, k1 = getSubKeys(key)
	else:
		raise ValueError("direction must either be \"ENCRYPT\" or \"DECRYPT\"")

	#initial permutation
	bits = permuteBits(data, Pinital)
	#split in half
	left1 = bits[:4]
	right1 = bits[4:]
	
	#Compute round one
	right2 = XOR(left1, F(right1, k1))
	left2 = right1
	#Compute round two
	result = XOR(left2, F(right2, k2)) + right2

	#inverse initial perm
	result = permuteBits(result, Pinverse)

	return result


#Input any amount of plaintext and returns the cyphertext
def encrypt(plaintext, key):
	cyphertext = ""
	#loop through bits and encrypt 8-bit blocks at a time
	for i in range(0, len(plaintext), 8):
		cyphertext += toy_des(plaintext[i:i+8], key, "ENCRYPT")

	return cyphertext

#takes input of binary cyphertext and returns plaintext
def decrypt(cyphertext, key):
	#loop through bits and decrypt 8-bit blocks at a time
	plaintext = ""
	for i in range(0, len(cyphertext), 8):
		plaintext += toy_des(cyphertext[i:i+8], key, "DECRYPT")

	return plaintext

