#include <iostream>
#include <cstdlib>
#include "FHEW/LWE.h"
#include "FHEW/FHEW.h"
#include "FHEW/distrib.h"

using namespace std;

void HomXOR(LWE::CipherText* res, const FHEW::EvalKey& EK, const LWE::CipherText& A, const LWE::CipherText& B ) {
	LWE::CipherText C, D;

	// A xor B = (A or B) and ~(A and B)
	BinGate and_g = static_cast<BinGate>(AND);
	BinGate or_g = static_cast<BinGate>(OR);
	BinGate nand_g = static_cast<BinGate>(NAND);

	//C = (A or B)
	FHEW::HomGate(&C, or_g, EK, A, B);

	//D = ~(A and B)
	FHEW::HomGate(&D, nand_g, EK, A, B);

	//A xor B = C and D
	FHEW::HomGate(res, and_g, EK, C, D);
}

int main() {

	cerr << "Setting up FHEW \n";
	FHEW::Setup();
	
	// Key used for encryption
	cerr << "Generating secret key ... ";
	LWE::SecretKey LWEsk;
	LWE::KeyGen(LWEsk);
	cerr << " Done.\n";

	// Key for performing functions
	cerr << "Generating evaluation key ... this may take a while ... ";
	FHEW::EvalKey EK;
	FHEW::KeyGen(&EK, LWEsk);
	cerr << " Done.\n\n";

	BinGate or_g = static_cast<BinGate>(OR);
	BinGate and_g = static_cast<BinGate>(AND);

	int a_pt1 = 1;
	int a_pt2 = 0;
	int a_pt3 = 1;
	LWE::CipherText a_1, a_2, a_3;
	LWE::Encrypt(&a_1, LWEsk, a_pt1);
	LWE::Encrypt(&a_2, LWEsk, a_pt2);
	LWE::Encrypt(&a_3, LWEsk, a_pt3);


	int b_pt1 = 0;
	int b_pt2 = 1;
	int b_pt3 = 0;
	LWE::CipherText b_1, b_2, b_3;
	LWE::Encrypt(&b_1, LWEsk, b_pt1);
	LWE::Encrypt(&b_2, LWEsk, b_pt2);
	LWE::Encrypt(&b_3, LWEsk, b_pt3);

	int dummy1 = 0;
	int dummy2 = 0;
	LWE::CipherText dummyCT1, dummyCT2, dummyRes;
	LWE::Encrypt(&dummyCT1, LWEsk, dummy1);
	LWE::Encrypt(&dummyCT2, LWEsk, dummy2);

	/* 
	 * Lazy adder:
	 * Full adder requires 2 XORs, 3 ANDs, and 2 ORs per bit
	 * Total = 64 XORs, 96 ANDs, 64 ORs
	 * Use real data for first 3 XORs
	 * Simulate the remainder of full adder by just performing operations on 0s (dummy variable)
	 */ 
	LWE::CipherText s_1, s_2, s_3;
	HomXOR(&s_1, EK, a_1, b_1);
	HomXOR(&s_2, EK, a_2, b_2);
	HomXOR(&s_3, EK, a_3, b_3);

	for(int i=0; i<96; i++) {
		if(i<61) {
			HomXOR(&dummyRes, EK, dummyCT1, dummyCT2);
		}

		if(i<64) {
			FHEW::HomGate(&dummyRes, or_g, EK, dummyCT1, dummyCT2);
		}

		FHEW::HomGate(&dummyRes, and_g, EK, dummyCT1, dummyCT2);
	}

	// Decrypt plaintext
	int dt_1 = LWE::Decrypt(LWEsk, s_1);
	int dt_2 = LWE::Decrypt(LWEsk, s_2);
	int dt_3 = LWE::Decrypt(LWEsk, s_3);

	cout << "Decrypted text is: " << dt_1 << dt_2 << dt_3 << endl;


}

