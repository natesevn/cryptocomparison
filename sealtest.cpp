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

using namespace std;
using namespace seal;

int main() {
	clock_t start;
	double duration;

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

	cout << "Parameters set." << endl;

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

	// Encode two integers as plaintext polynomials
	int value1 = 7;
    Plaintext plain1 = encoder.encode(value1);
    cout << "Encoded " << value1 << " as polynomial " << plain1.to_string() 
        << " (plain1)" << endl;

    int value2 = 8;
    Plaintext plain2 = encoder.encode(value2);
    cout << "Encoded " << value2 << " as polynomial " << plain2.to_string() 
        << " (plain2)" << endl;

	// Encrypt
	Ciphertext encrypted1, encrypted2;
    cout << "Encrypting plain1: ";
	start = clock();
    encryptor.encrypt(plain1, encrypted1);
	duration = ( clock() - start ) / (double) CLOCKS_PER_SEC;
    cout << "Done (encrypted1) in " << duration << endl;

    cout << "Encrypting plain2: ";
    encryptor.encrypt(plain2, encrypted2);
    cout << "Done (encrypted2)" << endl;

	// Show noise budget
	cout << "Noise budget in encrypted1: " 
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;
    cout << "Noise budget in encrypted2: " 
        << decryptor.invariant_noise_budget(encrypted2) << " bits" << endl;

	// Perform addition on ciphertext
	start = clock();
	evaluator.add_inplace(encrypted1, encrypted2);
	duration = ( clock() - start ) / (double) CLOCKS_PER_SEC;
	cout << "Addition in " << duration << endl;

	// Check noise budget after addition
	cout << "Noise budget in encrypted1 + encrypted2: " 
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;

	// Decrypt and decode
	Plaintext plain_result;
    cout << "Decrypting result: ";
	start = clock();
    decryptor.decrypt(encrypted1, plain_result);
	duration = ( clock() - start ) / (double) CLOCKS_PER_SEC;
    cout << "Done in " << duration << endl;

	// Print result
	cout << "Decoded integer: " << encoder.decode_int32(plain_result) << endl;

}