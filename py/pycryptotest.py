from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from datetime import datetime, timedelta
import random
import string

big_plaintext = 'a'*(5242880)
small_plaintext = 'a'*(1048576)
key = b'01234567890123456789012345678901'
iv = b'0123456789012345'
numTrials = 5

# PKCS#7 padding; https://stackoverflow.com/questions/43199123/encrypting-with-aes-256-and-pkcs7-padding
def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)

# Prints average time taken for 5 SHA operations
def timeSHA():
	totalTime = timedelta(0)

	for i in range(0, numTrials):

		# time hash operations
		startTime = datetime.now()
		hash = SHA256.new()
		hash.update(big_plaintext.encode('utf-8'))
		hash.digest()
		endTime = datetime.now()

		totalTime = totalTime + (endTime - startTime)

	print("Avg hash time: {0}".format(str(totalTime/numTrials)))
	return 

def timeAES():
	totalETime = timedelta(0)
	totalDTime = timedelta(0)

	for i in range(0, numTrials):

		# new AES instance for encryption
		cipher = AES.new(key, AES.MODE_ECB)

		# pad PT w/ PKCS#7
		data = pad(big_plaintext).encode()
		
		# encrypt data
		startTime = datetime.now()
		ciphertext = cipher.encrypt(data)
		endTime = datetime.now()
		totalETime = totalETime + (endTime - startTime)
		
		# new AES instance for decryption
		decipher = AES.new(key, AES.MODE_CBC, iv)

		# decrypt data
		startTime = datetime.now()
		decipheredtext = decipher.decrypt(ciphertext)
		endTime = datetime.now()
		totalDTime = totalDTime + (endTime - startTime)

	print("Avg encryption time: {0}".format(str(totalETime/numTrials)))
	print("Avg decryption time: {0}".format(str(totalDTime/numTrials)))
	return 

# Prints average time taken for 5 ChaCha encryptions and decryptions 
def timeChaCha():	
	totalETime = timedelta(0)
	totalDTime = timedelta(0)
	
	for i in range(0, numTrials):

		# new ChaCha instance for encryption
		cipher = ChaCha20.new(key=key)

		# encrypt data
		startTime = datetime.now()
		ciphertext = cipher.encrypt(big_plaintext.encode())
		endTime = datetime.now()
		totalETime = totalETime + (endTime - startTime)

		# new ChaCha instance for decryption
		decipher = ChaCha20.new(key=key, nonce=cipher.nonce)

		# decrypt data
		startTime = datetime.now()
		decipheredtext = decipher.decrypt(ciphertext)
		endTime = datetime.now()
		totalDTime = totalDTime + (endTime - startTime)	

	print("Avg encryption time: {0}".format(str(totalETime/numTrials)))
	print("Avg decryption time: {0}".format(str(totalDTime/numTrials)))
	return 

# Prints average time taken for 5 RSA encryptions and decryptions
def timeRSA():
	totalETime = timedelta(0)
	totalDTime = timedelta(0)

	# Prepare plaintext
	# Divide 1MB string into RSA block sizes of 214 bytes
	chunks, chunk_size = len(small_plaintext), len(small_plaintext)//4900
	pt_array = [small_plaintext[i:i+chunk_size] for i in range(0, chunks, chunk_size)]
	ct_array = []

	# generate private key
	key = RSA.generate(2048)

	for i in range(0, numTrials):
		# new RSA instance with key
		cipher = PKCS1_OAEP.new(key)

		# encrypt data
		startTime = datetime.now()
		for i in pt_array:
			ciphertext = cipher.encrypt(i.encode())
			ct_array.append(ciphertext)
		endTime = datetime.now()
		totalETime = totalETime + (endTime - startTime)

		# decrypt data
		startTime = datetime.now()
		for i in ct_array:
			decipheredtext = cipher.decrypt(i)
		endTime = datetime.now()
		totalDTime = totalDTime + (endTime - startTime)	

	print("Avg encryption time: {0}".format(str(totalETime/numTrials)))
	print("Avg decryption time: {0}".format(str(totalDTime/numTrials)))
	return 
	
if __name__ == '__main__':
	print("=========================================================================")
	print("AES256 Operations")
	timeAES()
	print("=========================================================================\n")

	print("=========================================================================")
	print("ChaCha Operations")
	timeChaCha()
	print("=========================================================================\n")

	print("=========================================================================")
	print("SHA Operations")
	timeSHA()
	print("=========================================================================\n")

	print("=========================================================================")
	print("RSA Operations")
	timeRSA()
	print("=========================================================================\n")