#include <cstddef>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <ctime>

#include "seal/seal.h"

const int numTrials = 5;

using namespace std;
using namespace seal;

int main() {
	clock_t start;
	double add_duration, e_duration, d_duration;

	cout << "=========================================================================" << endl;
	cout << "BFV using Microsoft SEAL." << endl;

	/* 
	 * Set up an instance of the EncryptionParameters class; 5 params
	 * 
	 * BFV has a noise budget determined by encryption parameters
	 * Homomorphic operations consume noise at a rate determined by same parameters
	 */
	EncryptionParameters parms(scheme_type::BFV);

	/*
	 * Polynomial modulus
	 * Must be a power of two
	 */
	parms.set_poly_modulus_degree(2048);

	/*
	 * Ciphertext coefficient modulus
	 * Highest impact on noise budget (larger means more, but reduces security)
	 */
	parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(2048));

	/*
	 * Plaintext modulus
	 * Determines size of plaintext data type
	 * Keep as small as possible for best performance
	 */
	parms.set_plain_modulus(1 << 8);

	// Construct SEALContext object
	auto context = SEALContext::Create(parms);

	/*
	 * Plaintexts in BFV are polynomials with coefficients integers modulo plain_modulus
	 * Need to encode data this way
	 */
	IntegerEncoder encoder(context);

	// Generate secret and public keys
	KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();

	// Get an instance of encryptor to encrypt
	Encryptor encryptor(context, public_key);

	// Computations on ciphertext performed using evaluator class
	Evaluator evaluator(context);

	// Get an instance of decryptor to decrypt
	Decryptor decryptor(context, secret_key);

	for(int i=0; i<numTrials; i++) {

		// Encode two integers as plaintext polynomials
		int value1 = 7;
		Plaintext plain1 = encoder.encode(value1);
		int value2 = 8;
		Plaintext plain2 = encoder.encode(value2);

		// Encrypt
		Ciphertext encrypted1, encrypted2;

		start = clock();
		encryptor.encrypt(plain1, encrypted1);
		e_duration = e_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;

		start = clock();
		encryptor.encrypt(plain2, encrypted2);
		e_duration = e_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;

		// Perform addition on ciphertext
		start = clock();
		evaluator.add_inplace(encrypted1, encrypted2);
		add_duration = add_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;

		// Decrypt and decode
		Plaintext plain_result;

		start = clock();
		decryptor.decrypt(encrypted1, plain_result);
		d_duration = d_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;
		
	}

	// Divide by 10 because encrypting 2 numbers 5 times each
	cout << "Avg encryption time: " << e_duration/(numTrials*2) << endl;
	cout << "Avg decryption time: " << d_duration/numTrials << endl;
	cout << "Avg addition time: " << add_duration/numTrials << endl;

	cout << "=========================================================================" << endl << endl;
}