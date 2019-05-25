#include <sstream>
#include <iostream>
#include <cstring>
#include <ctime>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>

using namespace std;

// Error handler; prints an error and exits program
void handleErrors(int status) {

	if(status == 0) {
		cout << "Something went wrong with decryption." << endl;
		exit(EXIT_FAILURE);
	} else if (status == 1) {
		cout << "Something went wrong with the encryption." << endl;
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
	double duration;

	EVP_CIPHER_CTX *ctx;

	unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
	unsigned char *iv = (unsigned char *)"0123456789012345";

	// Variables to store lengths
	int lenE, lenD;
	int ciphertext_len;
	int decryptedtext_len;

	// Buffers from cipher and result
	unsigned char ciphertext[128];
	unsigned char decryptedtext[128];

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
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &lenE, plaintext, plaintext_len))
			handleErrors(1);
	ciphertext_len = lenE;

	// Finalize encryption
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + lenE, &lenE)) 
		handleErrors(1);
	ciphertext_len += lenE;

	duration = ( std::clock() - start ) / (double) CLOCKS_PER_SEC;

	cout << "Cipher in hex: " << endl;
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
	cout <<"Time taken: " << duration << endl << endl;

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
	if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &lenD, ciphertext, ciphertext_len))
			handleErrors(0);
		decryptedtext_len = lenD;

	// Finalize decryption
	if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + lenD, &lenD)) 
		handleErrors(0);
		decryptedtext_len += lenD;

	duration = ( std::clock() - start ) / (double) CLOCKS_PER_SEC;

	decryptedtext[decryptedtext_len] = '\0';
	string result(reinterpret_cast<char*>(decryptedtext));
	cout << "Decrypted text: " << endl << result << endl;
	cout <<"Time taken: " << duration << endl;

	// Delete context object
	EVP_CIPHER_CTX_free(ctx);

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
	double duration;

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

	unsigned char ciphertext[256];
	unsigned char decryptedtext[256];
	int encrypt_len, decrypt_len;

	// Time encryption
	start = clock();
	if((encrypt_len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, keypair, RSA_PKCS1_PADDING)) == -1) {
		handleErrors(1);
	}
	duration = ( std::clock() - start ) / (double) CLOCKS_PER_SEC;

	cout << "Cipher is: " << endl;
	BIO_dump_fp (stdout, (const char *)ciphertext, encrypt_len);
	cout <<"Time taken: " << duration << endl << endl;

	// Time decryption
	start = clock();
	if(RSA_private_decrypt(encrypt_len, ciphertext, decryptedtext, keypair, RSA_PKCS1_PADDING) == -1) {
		handleErrors(1);
	}
	duration = ( std::clock() - start ) / (double) CLOCKS_PER_SEC;

	string result(reinterpret_cast<char*>(decryptedtext));
	cout << "Decrypted text: " << endl << result << endl;
	cout <<"Time taken: " << duration << endl;

	RSA_free(keypair);

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

	unsigned char digest[SHA256_DIGEST_LENGTH];

	SHA256_CTX sha256;

	if(1 != SHA256_Init(&sha256))
		handleErrors(2);
	
	// Hash operation
	start = clock();
	if(1 != SHA256_Update(&sha256, message, message_len))
		handleErrors(2);
	if(1 != SHA256_Final(digest, &sha256))
		handleErrors(2);
	duration = ( std::clock() - start ) / (double) CLOCKS_PER_SEC;

	cout << "Hash is: " << endl;
	BIO_dump_fp (stdout, (const char *)digest, SHA256_DIGEST_LENGTH);
	cout <<"Time taken: " << duration << endl;
		
	return;
}


int main() {
	const EVP_CIPHER* aes256 = EVP_aes_128_cbc();
	const EVP_CIPHER* chacha = EVP_chacha20();

	unsigned char *plaintext = (unsigned char *)"abc";

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