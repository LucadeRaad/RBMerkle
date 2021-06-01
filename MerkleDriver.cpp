#include <iostream>
#include <vector>
#include <string>
#include <queue>
#include <cstdlib>
#include <ctime>

#include "cryptlib.h"
#include "sha.h"

#include "MerkleRBTree.h"

using namespace std;
using namespace CryptoPP;

#define NUM_MESSAGES 1000 // 1000 by default

// you might want this for debugging
string byte_to_hex(const string& input) {
    static const char* const vals = "0123456789ABCDEF"; // hex characters to map to
    int len = input.length();

	string output;
	output.reserve(2*len); // hex output takes up 2 bytes per 1 byte of data
	for (int i = 0; i < len; i++) {
		const unsigned char c = input[i];   // select the character
		output.push_back(vals[c >> 4]);  
		output.push_back(vals[c & 15]);
	}
	return output;
}

int main () {

// this code is just an example of how to use the SHA-256 hash.  You can get rid of it 

	SHA256 hash;	
//    byte digest[ CryptoPP::SHA256::DIGESTSIZE ];
//    string message = "This is an example";
//    hash.CalculateDigest( digest, (byte*) message.c_str(), message.length() );
	
//    cout << byte_to_hex(string((char*)digest, SHA256::DIGESTSIZE)) << endl;
//	return 0;

/* ----------------   Driver Code --------------------   */

	
	srand((unsigned)time(0));
	MerkleTree merkle;
	
	int messageNumToVerify = rand() % NUM_MESSAGES;
	unsigned int uniqueID;
    string messageToVerify;
	string message;

	// build the merkle tree
	for (int i = 0; i < NUM_MESSAGES; i++) {
		message = "";
		for (int j = 0; j < rand() % 65535; j++) {  // messages can be up to 65535 bytes
			message += char(65 + rand() % 26);   // generate random capital letters
		}

		if (i == messageNumToVerify) {
			messageToVerify = message;
		}

		byte digest[ CryptoPP::SHA256::DIGESTSIZE ];
		hash.CalculateDigest( digest, (byte*) message.c_str(), message.length() );
		merkle.Insert(digest, i * SCALING);
	}

	// verify an element in the merkle tree
	byte digest[ CryptoPP::SHA256::DIGESTSIZE ];
	hash.CalculateDigest( digest, (byte*) messageToVerify.c_str(), messageToVerify.length() );

	if (merkle.Verify(digest, messageNumToVerify * SCALING)) {
		cout << "Message Verified Correctly" << endl;
	}
	else {
		cout << "ERROR" << endl;
	}

	// modify the element
	messageToVerify += 'a';   // this message can't exist because I only use capital letters
	hash.CalculateDigest( digest, (byte*) messageToVerify.c_str(), messageToVerify.length() );

	// verify that it isn't in the merkle tree
	if (merkle.Verify(digest, messageNumToVerify*SCALING)) {
		cout << "ERROR" << endl;
	}
	else {
		cout << "Message Verification Failed Correctly" << endl;
	}

	return 0;
}
