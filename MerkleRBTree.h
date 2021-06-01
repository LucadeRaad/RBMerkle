#ifndef MERKLERBTREE_H
#define MERKLETREE_H

#include <iostream>

#include "cryptlib.h"
#include "sha.h"

using namespace std;
using namespace CryptoPP;

#define SCALING 100
#define BITS_PER_BYTE 8
#define RED 0
#define BLACK 1

class MerkleTree {
    // Each struct can efficiently hold the color for 8 nodes
    struct bitStruct {
        unsigned char b0 : 1, b1 : 1, b2 : 1, b3 : 1, b4 : 1, b5 : 1, b6 : 1, b7 : 1; //, b8 : 1;
    };

    // MerkleNode holds a digest which is a unique hash or a hash of its leaf
    // nodes. It also holds a pointer to its parent to make rotating easier.
    struct MerkleNode {
        byte digest[CryptoPP::SHA256::DIGESTSIZE];

        int key;

        MerkleNode* left = nullptr;

        MerkleNode* right = nullptr;

        MerkleNode* parent = nullptr;        
    };

public:
    MerkleTree () {
        root_ = nullptr;
        colors_.push_back(*(new bitStruct));
	};

    void Insert(const byte digest[], const unsigned int key);
    bool Verify(const byte digest[], const unsigned int key);

private:
    MerkleNode* root_;  // Pointer to the root

    // Each bitStruct holds colors for 8 nodes. Vector increases in size to
    // accomodate more nodes needing their color
    vector<bitStruct> colors_;

    // For calculating digest of nodes
    SHA256 hash;

    void FastInsert(MerkleNode* node);

    void RebalanceRedBlackTree(MerkleNode* node);

    void ReMerkle();
    void ReMerkleHelper(MerkleNode* node);

    void GetHash(byte* insertDigest, MerkleNode* node);
    bool IsHashEquals(const byte* x, const byte* y);

    int GetNodeColor(const MerkleNode* node);
    void SetNodeColor(const MerkleNode* node, const int color);

    void RotateLeft(MerkleNode* node);
};

#endif  // MERKLERBTREE_H
