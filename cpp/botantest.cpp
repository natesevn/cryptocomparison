#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/dl_group.h>
#include <botan/rsa.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/botan.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <iostream>
#include <ctime>

const int numTrials = 5;

using namespace std;

/*
 * Performs AES encryption and decryption operations
 * Prints time taken for operations to complete
 * @plaintext: plaintext to be encrypted then decrypted
 */
int timeAESOp(string plaintext) {
	clock_t start;
	double e_duration=0, d_duration=0;

	for(int i=0; i<numTrials; i++) {

		// Get RNG
		Botan::AutoSeeded_RNG rng;

		// Get key and iv
		const vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C2B7E151628AED2A6ABF7158809CF4F3C");
		Botan::secure_vector<uint8_t> iv = rng.random_vec(16);

		// Create encrypt object
		unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::ENCRYPTION);
		enc->set_key(key);

		// Copy input data to a buffer that will be encrypted
		Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data()+plaintext.length());

		// Encrypt
		// Time encryption
		start = clock();
		enc->start(iv);
		enc->finish(pt);
		e_duration = e_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;

		// Create decrypt object
		unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::DECRYPTION);
		dec->set_key(key);

		// Copy ciphertext into buffer that will be decrypted
		Botan::secure_vector<uint8_t> dt(pt);

		// Decrypt
		// Time decryption
		start = clock();
		dec->start(iv);
		dec->finish(dt);
		d_duration = d_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;

		string str(dt.begin(), dt.end());

	}

	cout << "Avg encryption time: " << e_duration/numTrials << endl;
	cout << "Avg decryption time: " << d_duration/numTrials << endl;

	return 0;
}

/*
 * Performs ChaCha encryption and decryption operations
 * Prints time taken for operations to complete
 * @plaintext: plaintext to be encrypted then decrypted
 */
int timeChaChaOp(string plaintext) {
	clock_t start;
	double e_duration=0, d_duration=0;

	for(int i=0; i<numTrials; i++) {
	
		// Prepare plaintext
		Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data()+plaintext.length());

		// Setup key and IV
		const vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
		unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
		vector<uint8_t> iv(8);
		rng->randomize(iv.data(),iv.size());

		// Create stream cipher object
		unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("ChaCha(20)"));

		// Set key and IV
		cipher->set_key(key);
		cipher->set_iv(iv.data(),iv.size());

		// Encrypt
		start = clock();
		cipher->encipher(pt);
		e_duration = e_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;

		// Reset cipher object
		cipher->clear();
		cipher->set_key(key);
		cipher->set_iv(iv.data(),iv.size());

		// Decrypt
		start = clock();
		cipher->encipher(pt);
		d_duration = d_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;

		string str(pt.begin(), pt.end());
	
	}

	cout << "Avg encryption time: " << e_duration/numTrials << endl;
	cout << "Avg decryption time: " << d_duration/numTrials << endl;

}

/*
 * Performs SHA256 hashing
 * Prints time taken for operations to complete
 * @plaintext: plaintext to be hashed
 */
int timeHashOp(string plaintext) {
	clock_t start;
	double duration;

	for(int i=0; i<numTrials; i++) {
		// Initialize hash object
		unique_ptr<Botan::HashFunction> hash1(Botan::HashFunction::create("SHA-256"));

		start = clock();
		hash1->update(plaintext);
		duration = duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;
		
	}

	cout << "Avg hash time: " << duration/numTrials << endl;
	return 0;
}

/*
 * Performs RSA encryption and decryption operations
 * Prints time taken for operations to complete
 * @plaintext: plaintext to be encrypted then decrypted
 */
int timeRSAOp(string plaintext) {
	clock_t start;
	double e_duration=0, d_duration=0;

	for(int i=0; i<numTrials; i++) {

		// Prepare plaintext
		Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data()+plaintext.length());

		// Get RNG
		Botan::AutoSeeded_RNG rng;

		// Generate new RSA private key
		Botan::RSA_PrivateKey key(rng, 2048);

		// Encode private key
		string priv = Botan::PKCS8::PEM_encode(key);

		// Store public, private keys as memory data source
		Botan::DataSource_Memory key_priv(priv);

		// Load public, private key
		Botan::PKCS8_PrivateKey *priv_rsa = Botan::PKCS8::load_key(key_priv, rng);
		unique_ptr<Botan::Private_Key> kp(priv_rsa);

		// Encrypt with public key
		Botan::PK_Encryptor_EME enc(*kp, rng, "EME-PKCS1-v1_5");

		start = clock();
		vector<uint8_t> ct = enc.encrypt(pt, rng);
		e_duration = e_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;

		// Decrypt with private key
		Botan::PK_Decryptor_EME dec(*kp, rng, "EME-PKCS1-v1_5");

		start = clock();
		Botan::secure_vector<uint8_t> dt=   dec.decrypt(ct);
		d_duration = d_duration + ( clock() - start ) / (double) CLOCKS_PER_SEC;

	}

	cout << "Avg encryption time: " << e_duration/numTrials << endl;
	cout << "Avg decryption time: " << d_duration/numTrials << endl;

	return 0;
}

int main() {
	
	string pt = "abc";

	cout << "=========================================================================" << endl;
	cout << "AES256 Operations" << endl;
   	timeAESOp(pt);
	cout << "=========================================================================" << endl << endl;

	cout << "=========================================================================" << endl;
	cout << "ChaCha Operations" << endl;
   	timeChaChaOp(pt);
	cout << "=========================================================================" << endl << endl;

	cout << "=========================================================================" << endl;
	cout << "SHA256 Operations" << endl;
   	timeHashOp(pt);
	cout << "=========================================================================" << endl << endl;

	cout << "=========================================================================" << endl;
	cout << "RSA Operations" << endl;
   	timeRSAOp(pt);
	cout << "=========================================================================" << endl << endl;
   
   return 0;
}