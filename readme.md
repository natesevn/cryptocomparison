# Comparison Between Different Crypto Libraries

|**Cipher Type**	|**Algo**				|	  						||||
|---------------|-------------------|---------------|-----------|-------------------|---------------|
|				|					|**C++/OpenSSL**|**C++/Botan**	|**Py/Cryptodome**		|**Py/Cryptography**|
|				|					|				|		  	|					|				|
|Block			|AES256				|E: 0.0025	    |E: 0.0012	|E: 0.0028			|E: 0.0110		|
|				|					|D: 0.0026	    |D: 0.0012 	|D: 0.0129			|D: 0.0030		|
|				|					|			    |		    |					|				|
|Stream			|ChaCha20			|E: 0.0098	    |E: 0.0021	|E: 0.0156			|E: 0.0061|
|				|					|D: 0.0099	    |D: 0.0021 	|D: 0.0130 			|D: 0.0031|
|				|					|			    |		    |					|				|
|Asymmetric		|RSA				|E: 0.2049  	|E: 0.2222	|E: 2.2997			|E: 0.1510|
|				|					|D: 4.3133	    |D: 6.8006 	|D: 20.9465			|D: 8.1566|
|				|					|				|		  	|					|				|
|Hash 			|SHA256				|0.0127			|0.0158		|0.0225				|0.0112		|
|				|					|				|		  	|					|				|
|||||||
|				|					|**C++/SEAL**		|**C++/fhew**	|**Py/nufhe**		|**Py/fhel** 		|
|||||||
|FHE			|					|E: 3e-04			|E:	1.5e-04		|E:	0.0024			|E: 0.0015			|
|				|					|D:	1.5e-04			|D:	2.35e-05	|D:	0.0025			|D: 1.9e-04			|
|				|					|A:	1.34e-05		|A:	24.114		|A:	0.0048			|A: 0.0031			|

Table:
E: Encryption,
D: Decryption,
A: Addition

## Algorithm Information
**Block Cipher**: `AES256` in ECB mode 

**Stream Cipher**: `ChaCha20`

**Hash**: `SHA256`

**Asymmetric Cipher**: `RSA` with 2048-bit modulus

**FHE Libraries**:  `SEAL` and `fhew` with 2048-bit modulus for `C++`. `fhel` and `nufhe` with 2048-bit modulus for `Python`.



\newpage


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

Requires FFTW 3: http://www.fftw.org/download.html

Only allows binary gate operations. Clone the repo and run `make`. 

`g++ fhewtest.cpp -g -I/home/$USER/Include/ -L/home/$USER/Include/FHEW/ -ansi -lfhew -lfftw3`

## Python Libraries

### Cryptodome
https://pycryptodome.readthedocs.io/en/latest/src/installation.html

`pip install pycryptodome`

Built on pycrypto.

### Cryptography
https://cryptography.io/en/latest/installation/

`pip install cryptography`

### Pyfhel
https://github.com/ibarrond/Pyfhel

`pip install pyfhel`

### Nufhe
https://github.com/nucypher/nufhe

`pip install nufhe`

Requires either CUDA if using an nVidia GPU, or OpenCL. 


\newpage





# Hardware Information
**OS:** Manjaro Linux x86_64 

**Host:** MacBookPro11,3 1.0 

**Kernel:** 4.19.42-1-MANJARO

**CPU:** Intel i7-4980HQ (8) @ 4.000GHz 

**GPU:** NVIDIA GeForce GT 750M Mac Edition 
 
**Memory:** 15948MiB 


