from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

plaintext = 'abc'
key = b'01234567890123456789012345678901'
iv = b'0123456789012345'

# PKCS#7 padding; https://stackoverflow.com/questions/43199123/encrypting-with-aes-256-and-pkcs7-padding
def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)

def timeSHA():
	hash = SHA256.new()
	hash.update(plaintext.encode('utf-8'))
	res = hash.digest()
	return res

def timeAES():
	cipher = AES.new(key, AES.MODE_CBC, iv)

	# pad PT w/ PKCS#7
	data = pad(plaintext).encode()
	ciphertext = cipher.encrypt(data)

	print(ciphertext)

	decipher = AES.new(key, AES.MODE_CBC, iv)
	decipheredtext = decipher.decrypt(ciphertext)

	print(decipheredtext)

	return 

def timeChaCha():	
	cipher = ChaCha20.new(key=key)
	ciphertext = cipher.encrypt(plaintext.encode())

	print(ciphertext.hex())

	decipher = ChaCha20.new(key=key, nonce=cipher.nonce)
	decipheredtext = decipher.decrypt(ciphertext)

	print(decipheredtext)

	return 

def timeRSA():
	key = RSA.generate(2048)
	
	cipher = PKCS1_OAEP.new(key)
	ciphertext = cipher.encrypt(plaintext.encode())

	print(ciphertext.hex())

	decipheredtext = cipher.decrypt(ciphertext)

	print(decipheredtext)

	return 
	

timeAES()