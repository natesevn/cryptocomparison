import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timedelta

big_plaintext = 'a'*(5242880)
small_plaintext = 'a'*(1048576)
plaintext = 'abc'
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
		# create new hash instance
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

		# time hash operations
		startTime = datetime.now()
		digest.update(big_plaintext.encode())
		digest.finalize()
		endTime = datetime.now()

		totalTime = totalTime + (endTime - startTime)

	print("Avg hash time: {0}".format(str(totalTime/numTrials)))
	return

# Prints average time taken for 5 AES encryptions and decryptions 
def timeAES():
	totalETime = timedelta(0)
	totalDTime = timedelta(0)

	backend = default_backend()

	data = pad(big_plaintext).encode()

	for i in range(0, numTrials):

		# initialize new AES cipher
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

		# get encrypting and decrypting cipher instances
		encryptor = cipher.encryptor()
		decryptor = cipher.decryptor()

		# encrypt data
		startTime = datetime.now()
		ct = encryptor.update(data) + encryptor.finalize()
		endTime = datetime.now()
		totalETime = totalETime + (endTime - startTime)

		# decrypt data
		startTime = datetime.now()
		dt = decryptor.update(ct) + decryptor.finalize()
		endTime = datetime.now()
		totalDTime = totalDTime + (endTime - startTime)

	print("Avg encryption time: {0}".format(str(totalETime/numTrials)))
	print("Avg decryption time: {0}".format(str(totalDTime/numTrials)))
	return

# Prints average time taken for 5 ChaCha encryptions and decryptions 
def timeChaCha():
	totalETime = timedelta(0)
	totalDTime = timedelta(0)

	# get random nonce
	nonce = os.urandom(16)
	algorithm = algorithms.ChaCha20(key, nonce)

	for i in range(0, numTrials):

		# initialize new ChaCha cipher
		cipher = Cipher(algorithm, mode=None, backend=default_backend())

		# get encrypting and decrypting cipher instances
		encryptor = cipher.encryptor()
		decryptor = cipher.decryptor()

		# encrypt data
		startTime = datetime.now()
		ct = encryptor.update(big_plaintext.encode())
		endTime = datetime.now()
		totalETime = totalETime + (endTime - startTime)

		# decrypt data
		startTime = datetime.now()
		dt = decryptor.update(ct)
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

	# generate keys
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)
	public_key = private_key.public_key()

	for i in range(0, numTrials):

		# encrypt
		startTime = datetime.now()
		for i in pt_array:
			ct = public_key.encrypt(
				i.encode(),
				padding.PKCS1v15()
			)
			ct_array.append(ct)
		endTime = datetime.now()
		totalETime = totalETime + (endTime - startTime)

		# decrypt
		startTime = datetime.now()
		for i in ct_array:
			dt = private_key.decrypt(
				i,
				padding.PKCS1v15()
			)
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
