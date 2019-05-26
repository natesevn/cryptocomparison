from Pyfhel import Pyfhel, PyPtxt, PyCtxt

# Creating context and KeyGen
HE = Pyfhel()
HE.contextGen(p=2048)
HE.keyGen()

# Encrypt integers
pt1 = 5
pt2 = 2
ct1 = HE.encryptInt(pt1)
ct2 = HE.encryptInt(pt2)

# Operate on integers
ctSum = ct1 + ct2

# Decrypt result
res = HE.decryptInt(ctSum)

print(res)
