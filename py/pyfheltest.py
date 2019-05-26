from Pyfhel import Pyfhel, PyPtxt, PyCtxt
from datetime import datetime, timedelta

numTrials = 5
totalETime = timedelta(0)
totalATime = timedelta(0)
totalDTime = timedelta(0)

print("=========================================================================")
print("Pyfhel Operations")

# Creating context and KeyGen
HE = Pyfhel()
HE.contextGen(p=2048)
HE.keyGen()


for i in range(0, numTrials):
	
	# Encrypt integers
	startTime = datetime.now()
	pt1 = 5
	pt2 = 2
	ct1 = HE.encryptInt(pt1)
	ct2 = HE.encryptInt(pt2)
	endTime = datetime.now()
	totalETime = totalETime + (endTime - startTime)

	# Operate on integers
	startTime = datetime.now()
	ctSum = ct1 + ct2
	endTime = datetime.now()
	totalATime = totalATime + (endTime - startTime)

	# Decrypt result
	startTime = datetime.now()
	res = HE.decryptInt(ctSum)
	endTime = datetime.now()
	totalDTime = totalDTime + (endTime - startTime)

print("Avg encryption time: {0}".format(str(totalETime/(numTrials*2))))
print("Avg decryption time: {0}".format(str(totalDTime/numTrials)))
print("Avg addition time: {0}".format(str(totalETime/numTrials)))
print("=========================================================================\n")
