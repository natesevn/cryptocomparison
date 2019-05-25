from Crypto.Hash import SHA256

plaintext = 'abc'

hash = SHA256.new()
hash.update(plaintext.encode('utf-8'))
res = hash.digest()
print(res)