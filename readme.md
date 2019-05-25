# Comparison Between Different Crypto Libraries
				
|Cipher Type	|Algo				|Language/Library		  |
|---------------|-------------------|-------------------------|
|Block			|AES256_CBC			|C++/OpenSSL	|C++/Botan|
|Stream			|ChaCha20			|C++/OpenSSL	|C++/Botan|
|Asymmetrickey	|RSA_PKCS1_PADDING	|C++/OpenSSL	|C++/Botan|
|Hash function	|SHA256				|C++/OpenSSL	|C++/Botan|
|FHE			|					|C++/FHEW		|C++/SEAL |

## Installation and Compilation Instructions

### OpenSSL
`g++ openssltest.cpp -g -lcrypto`

### Botan
https://botan.randombit.net/manual/building.html

`g++ botantest.cpp -g -I/usr/include/botan-2 -lbotan-2 -lbz2 -ldl -llzma -lrt -lz`

### SEAL
Requires CMAKE

https://github.com/microsoft/SEAL#building-and-using-microsoft-seal

`g++ sealtest.cpp -g -lseal -lpthread -std=c++17`
