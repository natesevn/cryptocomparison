#include <sstream>
#include <iostream>
#include <cstring>
#include <ctime>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>

const int numTrials = 5;

using namespace std;

// Error handler; prints an error and exits program
void handleErrors(int status) {

	if(status == 0) {
		cout << "Something went wrong with decryption." << endl;
		exit(EXIT_FAILURE);
	} else if (status == 1) {
		cout << "Something went wrong with the encryption." << endl;
		unsigned long test = ERR_get_error();
		cout << test << endl;
		exit(EXIT_FAILURE);
	} else if (status == 2) {
		cout << "Something went wrong with hashing." << endl;
		exit(EXIT_FAILURE);
	} else {
			ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

/*
 * Performs symmetric encryption and decryption operations
 * Prints time taken for operations to complete
 * @plaintext: plaintext to be encrypted then decrypted
 * @plaintext_len: plaintext length
 * @algo: algorithm to use
 */
int timeCipherOp(unsigned char *plaintext, unsigned int plaintext_len, const EVP_CIPHER* algo) {
	clock_t start;
	double e_duration=0, d_duration=0;

	for(int i=0; i<numTrials; i++) {

		EVP_CIPHER_CTX *ctx;

		unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
		unsigned char *iv = (unsigned char *)"0123456789012345";

		// Variables to store lengths
		int lenE, lenD;
		int ciphertext_len;
		int decryptedtext_len;

		// Buffers from cipher and result
		unsigned char ciphertext[512];
		unsigned char decryptedtext[512];

		/* Encrypt */

		// Create and initialise the context 
		if(!(ctx = EVP_CIPHER_CTX_new())) 
			handleErrors(1);

		// Initialize encryption operation
		if(1 != EVP_EncryptInit_ex(ctx, algo, NULL, key, iv))
				handleErrors(1);

		// Time encryption
		start = clock();

		// Encrypt given message to provided output
		for(int i=0; i<40960; i++) {
			if(1 != EVP_EncryptUpdate(ctx, ciphertext, &lenE, plaintext, plaintext_len))
					handleErrors(1);
			ciphertext_len = lenE;
		}

		// Finalize encryption
		if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + lenE, &lenE)) 
			handleErrors(1);
		ciphertext_len += lenE;

		e_duration = e_duration + ( std::clock() - start ) / (double) CLOCKS_PER_SEC;

		// Delete context object
		EVP_CIPHER_CTX_free(ctx);

		/* Decrypt */

		// Create and initialise the context 
		if(!(ctx = EVP_CIPHER_CTX_new())) 
			handleErrors(0);
		
		// Initialize decryption operation
		if(1 != EVP_DecryptInit_ex(ctx, algo, NULL, key, iv))
				handleErrors(0);

		// Time decryption
		start = clock();

		// Decrypt given message to provided output
		for(int i=0; i<40960; i++) {
			if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &lenD, ciphertext, ciphertext_len))
					handleErrors(0);
				decryptedtext_len = lenD;
		}

		// Finalize decryption
		if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + lenD, &lenD)) 
			handleErrors(0);
			decryptedtext_len += lenD;

		d_duration = d_duration + ( std::clock() - start ) / (double) CLOCKS_PER_SEC;

		// Delete context object
		EVP_CIPHER_CTX_free(ctx);

	}

	cout << "Avg encryption time: " << e_duration/numTrials << endl;
	cout << "Avg decryption time: " << d_duration/numTrials << endl;

	return 0;
}

/*
 * Performs RSA encryption and decryption operations
 * Prints time taken for operations to complete
 * @plaintext: plaintext to be encrypted then decrypted
 * @plaintext_len: plaintext length
 */
int timeRSAOp(unsigned char *plaintext, unsigned int plaintext_len) {
	clock_t start;
	double e_duration=0, d_duration=0;

	for(int i=0; i<numTrials; i++) {

		// Generate RSA key
		// Setup required data structures
		RSA *keypair = RSA_new();
		BIGNUM *bne = NULL;

		// Set public exponent = 65537
		unsigned long e = RSA_F4;
		bne = BN_new();
		if(1 != BN_set_word(bne, e))
			handleErrors(1);

		// Get 2048-bit key
		if(1 != RSA_generate_key_ex(keypair, 2048, bne, NULL))
			handleErrors(1);

		unsigned char ciphertext[512];
		unsigned char decryptedtext[512];
		int encrypt_len, decrypt_len;

		// Time encryption
		start = clock();
		for(int i=0; i<8192; i++) {
			if((encrypt_len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, keypair, RSA_PKCS1_PADDING)) == -1) {
				handleErrors(1);
			}
		}
		e_duration = e_duration + ( std::clock() - start ) / (double) CLOCKS_PER_SEC;

		// Time decryption
		start = clock();
		for(int i=0; i<8192; i++) {
			if(RSA_private_decrypt(encrypt_len, ciphertext, decryptedtext, keypair, RSA_PKCS1_PADDING) == -1) {
				handleErrors(1);
			}
		}
		d_duration = d_duration + ( std::clock() - start ) / (double) CLOCKS_PER_SEC;

		RSA_free(keypair);

	}

	cout << "Avg encryption time: " << e_duration/numTrials << endl;
	cout << "Avg decryption time: " << d_duration/numTrials << endl;

	return 0;
}

/*
 * Performs hashing
 * Prints time taken for operation to complete
 * @message: message to be hashed
 * @message_len: plaintext length
 */
void timeHashOp(unsigned char *message, unsigned int message_len) {
	clock_t start;
	double duration;

	for(int i=0; i<numTrials; i++) {
		unsigned char digest[SHA256_DIGEST_LENGTH];

		SHA256_CTX sha256;

		if(1 != SHA256_Init(&sha256))
			handleErrors(2);
		
		// Hash operation
		start = clock();
		for(int i=0; i<40960; i++) {
			if(1 != SHA256_Update(&sha256, message, message_len))
				handleErrors(2);
		}
		if(1 != SHA256_Final(digest, &sha256))
			handleErrors(2);
		duration = duration + ( std::clock() - start ) / (double) CLOCKS_PER_SEC;
	}
	
	cout << "Avg hash time: " << duration/numTrials << endl;
	return;
}


int main() {
	const EVP_CIPHER* aes256 = EVP_aes_128_ecb();
	const EVP_CIPHER* chacha = EVP_chacha20();

	// Instead of using 5MB string, use 128 bytes instead
	// In each crypto primitive, do 40960 operations of 128 bytes 
	// to simulate performing operations on 5MB file
	// Do 8192 for RSA to simulate 1MB file
	unsigned char plaintext[128] = {0};
	fill(plaintext, plaintext + 128, 'a');

	/* AES */
	cout << "=========================================================================" << endl;
	cout << "AES256 Operations" << endl;
	timeCipherOp(plaintext, strlen ((char *)plaintext), aes256);
	cout << "=========================================================================" << endl << endl;

	/* ChaCha */
	cout << "=========================================================================" << endl;
	cout << "ChaCha Operations" << endl;
	timeCipherOp(plaintext, strlen ((char *)plaintext), chacha);
	cout << "=========================================================================" << endl << endl;

	/* SHA256 Hash */
	cout << "=========================================================================" << endl;
	cout << "SHA256 Hash" << endl;
	timeHashOp(plaintext, strlen ((char *)plaintext));
	cout << "=========================================================================" << endl << endl;

	/* RSA Encryption */
	cout << "=========================================================================" << endl;
	cout << "RSA Operations" << endl;
	timeRSAOp(plaintext, strlen ((char *)plaintext));
	cout << "=========================================================================" << endl << endl;
	
	return 0;
}