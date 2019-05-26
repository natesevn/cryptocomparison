---
title: Crypto Libary Comparison
author: Nicholas Handaja
date: \today
geometry: margin=2cm
---

# Comparison Between Different Crypto Libraries

|**Cipher Type**	|**Algo**				|	  						|
|---------------|-------------------|---------------|-----------|-------------------|---------------|
|				|					|**C++/OpenSSL**|**C++/Botan**	|**Py/Cryptodome**		|**Py/Cryptography**|
|				|					|				|		  	|					|				|
|Block			|AES256_CBC			|E: 3.4e-06	    |E: 2.4e-06	|E: 1.8e-04			|E: 1.2e-05		|
|				|					|D: 2e-06	    |D: 1.2e-06 |D: 9e-07			|D: 7e-07		|
|				|					|			    |		    |					|				|
|Stream			|ChaCha20			|E: 3e-06	    |E: 8e-07	|E: 8e-07			|E: 5e-07|
|				|					|D: 1.8e-06	    |D: 1e-06 	|D: 4e-07 			|D: 3e-07|
|				|					|			    |		    |					|				|
|Asymmetrickey	|RSA				|E: 4.06e-05    |E: 6.46e-05|E: 5.43-04			|E: 4.1e-06|
|				|					|D: 9.2e-04	    |D: 0.0016 	|D: 0.0015			|D: 6.25e-04|
|				|					|				|		  	|					|				|
|Hash function	|SHA256				|1.4e-06		|1.2e-06	|5.4e-05			|1.1e-06		|
|				|					|				|		  	|					|				|
|||||||
|				|					|**C++/SEAL**		|**C++/fhew**	|**Py/nufhe**		|**Py/fhel** 		|
|||||||
|FHE			|					|E: 3e-04			|E:	1.5e-04		|E:	0.0024			|E: 0.0015			|
|				|					|D:	1.5e-04			|D:	2.35e-05	|D:	0.0025			|D: 1.9e-04			|
|				|					|A:	1.34e-05		|A:	24.114		|A:	0.0048			|A: 0.0031			|




# Library Information

## C++ Libraries

### OpenSSL
Comes default with most Linux installations.

`g++ openssltest.cpp -g -lcrypto`

### Botan
https://botan.randombit.net/manual/building.html

Available on the AUR. 

`g++ botantest.cpp -g -I/usr/include/botan-2 -lbotan-2 -lbz2 -ldl -llzma -lrt -lz`

### SEAL
https://github.com/microsoft/SEAL#building-and-using-microsoft-seal

Requires CMAKE

`g++ sealtest.cpp -g -lseal -lpthread -std=c++17`

### FHEW
https://github.com/lducas/FHEW

Only allows binary gate operations. Clone the repo and run `make`. 

`g++ fhewtest.cpp -g -I/home/$USER/Include/ -L/home/$USER/Include/FHEW/ -ansi -lfhew -lfftw3`

## Python Libraries

### Cryptodome
`pip install pycryptodome`

Built on pycrypto.

### Cryptography
`pip install cryptography`

### Pyfhel
`pip install pyfhel`

### Nufhe
`pip install nufhe`

Requires either CUDA if using an nVidia GPU, or OpenCL. 


