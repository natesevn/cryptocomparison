import random
import nufhe
from datetime import datetime, timedelta

numTrials = 5
totalETime = timedelta(0)
totalATime = timedelta(0)
totalDTime = timedelta(0)

print("=========================================================================")
print("Nufhe Operations")

# start new nufhe instance
ctx = nufhe.Context()

# create secret_key to encrypt, cloud_key to apply operations
secret_key, cloud_key = ctx.make_key_pair()

# nufhe operates on bit arrays
bits1 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1]
bits2 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0]

# use dummy array to simulate full adder
dummy = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

for i in range(0, numTrials):

	# encrypt bits
	startTime = datetime.now()
	ciphertext1 = ctx.encrypt(secret_key, bits1)
	ciphertext2 = ctx.encrypt(secret_key, bits2)
	endTime = datetime.now()
	totalETime = totalETime + (endTime - startTime)

	dummyct = ctx.encrypt(secret_key, dummy)

	# calculations are done on virtual machine created from cloud key
	vm = ctx.make_virtual_machine(cloud_key)

	'''
	Lazy adder:
	Full adder requires 2 XORs, 3 ANDs, and 2 ORs per bit:
		sum = a xor b xor c
		carry = ab+bc+ca
	Total for 32-bit integers = 64 XORs, 96 ANDs, 64 ORs
	XOR'ing two 32-bit arrays = 64 XORs
	Simulate the remainder by just performing operations on dummy array
	'''
	startTime = datetime.now()

	# this would give the "actual" addition result
	result = vm.gate_xor(ciphertext1, ciphertext2)

	# simulate the rest of the adder circuit by performing operations on dummy variable
	dummyres = vm.gate_and(dummyct, dummyct)
	dummyres = vm.gate_and(dummyct, dummyct)
	dummyres = vm.gate_or(dummyct, dummyct)

	endTime = datetime.now()
	totalATime = totalATime + (endTime - startTime)

	# decrypt result
	startTime = datetime.now()
	result_bits = ctx.decrypt(secret_key, result)
	endTime = datetime.now()
	totalDTime = totalDTime + (endTime - startTime)

print("Avg encryption time: {0}".format(str(totalETime/(numTrials*2))))
print("Avg decryption time: {0}".format(str(totalDTime/numTrials)))
print("Avg addition time: {0}".format(str(totalETime/numTrials)))
print("=========================================================================\n")