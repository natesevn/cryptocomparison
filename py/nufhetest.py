import random
import nufhe

ctx = nufhe.Context()

# secret_key to encrypt, cloud_key to apply operations
secret_key, cloud_key = ctx.make_key_pair()

# nufhe operates on bit arrays
bits1 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1]
bits2 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0]
dummy = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

# encrypt bits
ciphertext1 = ctx.encrypt(secret_key, bits1)
ciphertext2 = ctx.encrypt(secret_key, bits2)
dummyct = ctx.encrypt(secret_key, dummy)

# calculations done on virtual machine created from cloud key
vm = ctx.make_virtual_machine(cloud_key)

'''
Lazy adder:
Full adder requires 2 XORs, 3 ANDs, and 2 ORs per bit
Total = 64 XORs, 96 ANDs, 64 ORs
XOR'ing two 32 bit arrays = 64 XORs
Simulate the remainder by just performing operations on dummy array
'''

# this would give me the "actual" addition result
result = vm.gate_xor(ciphertext1, ciphertext2)

# simulation
dummyres = vm.gate_and(dummyct, dummyct)
dummyres = vm.gate_and(dummyct, dummyct)
dummyres = vm.gate_or(dummyct, dummyct)

# decrypt result
result_bits = ctx.decrypt(secret_key, result)

for bits in result_bits:
	print(bits)