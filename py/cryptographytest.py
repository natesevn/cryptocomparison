import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

plaintext = 'abc'
key = b'01234567890123456789012345678901'
iv = b'0123456789012345'

# PKCS#7 padding; https://stackoverflow.com/questions/43199123/encrypting-with-aes-256-and-pkcs7-padding
def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)

def timeSHA():
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(plaintext.encode())
	#digest.finalize()

	print(digest.finalize())
	return

def timeAES():
	backend = default_backend()
	
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()

	data = pad(plaintext).encode()
	ct = encryptor.update(data) + encryptor.finalize()

	decryptor = cipher.decryptor()
	dt = decryptor.update(ct) + decryptor.finalize()

	print(dt)
	return

def timeChaCha():
	nonce = os.urandom(16)
	algorithm = algorithms.ChaCha20(key, nonce)

	cipher = Cipher(algorithm, mode=None, backend=default_backend())

	encryptor = cipher.encryptor()
	ct = encryptor.update(plaintext.encode())
	
	decryptor = cipher.decryptor()
	dt = decryptor.update(ct)

	print(dt)
	return

def timeRSA():
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)
	public_key = private_key.public_key()

	ct = public_key.encrypt(
		plaintext.encode(),
		padding.PKCS1v15()
	)

	dt = private_key.decrypt(
		ct,
		padding.PKCS1v15()
	)
	
	print(dt)

	return

timeRSA()