#include <iostream>
#include <cmath>

#include "cryptlib.h"
#include "sha.h"

#include "MerkleRBTree.h"

using namespace std;
using namespace CryptoPP;

// Takes a hash and key and turns them into a node to insert into the tree.
// Additional nodes are created when inserting to maintain the merkle tree.
// Nodes may be swapped or color changed to maintain the red black tree.
void MerkleTree::Insert(const byte digest[], const unsigned int key) {
    // Order goes-
    //            Create node from driver
    //            Balance red black tree
    //            Set merkle nodes
    //            Create merkle node
    //            Balance red black tree
    // Order is done so that a merkle node is never a leaf node when
    // merkle nodes are set
    MerkleNode* leafNode (new MerkleNode);
    leafNode->key = key;
    memcpy_s(leafNode->digest, 
             CryptoPP::SHA256::DIGESTSIZE, 
             digest, 
             CryptoPP::SHA256::DIGESTSIZE);

    FastInsert(leafNode);

    // Now we need to maintain the red black + merkle tree

    RebalanceRedBlackTree(leafNode);

    ReMerkle();

    MerkleNode* merkleNode (new MerkleNode);
    merkleNode->key = key + (SCALING / 2);

    FastInsert(merkleNode);

    RebalanceRedBlackTree(merkleNode);
}

// Verifies a node by finding it in the tree, then making sure that the merkle
// nodes up to the root are all legitimate
bool MerkleTree::Verify(const byte digest[], const unsigned int key) {
    MerkleNode* pointer = root_;
    
    while (pointer != nullptr) {
        if (key == pointer->key) {
            break;
        } else if (key < pointer->key) {
            pointer = pointer->left;
        } else {
            pointer = pointer->right;
        }
    }

    // Check if the digest provided equals the digest found with the key. If
    // true check that the digest found hashes with every merkle node
    if (!(IsHashEquals(digest, pointer->digest))) {
        return false;
    }

    while (pointer != root_) {
        pointer = pointer->parent;

        byte compareDigest[CryptoPP::SHA256::DIGESTSIZE];

        GetHash(compareDigest, pointer);

        if (!(IsHashEquals(compareDigest, pointer->digest))) {
            return false;
        }
    }
    return true; 
}

// Returns false if a single byte in the hash is different
bool MerkleTree::IsHashEquals(const byte* x, const byte* y) {
    for (int i = 0; i < CryptoPP::SHA256::DIGESTSIZE; i++) {
        if (x[i] != y[i]) {
            return false;
        }
    }
    return true;
}

// Every node created will be bigger than the last, this function was made with
// this in mind, nodes are put to the rightmost part of the tree.
void MerkleTree::FastInsert(MerkleNode* insert) {
    if ((insert->key / (SCALING / 2) ) % 8 == 0) {
        colors_.push_back(*(new bitStruct));
    }

    // If MerkleTree is empty
    if (root_ == nullptr) {
        root_ = insert;
        // Follows bullet point 3 on page 14 of balanced tree ppt
        SetNodeColor(insert, BLACK);
        return;
    }

    MerkleNode* pointer = root_;

    // Every Key is always bigger than the last.
    while (pointer->right != nullptr) {
        pointer = pointer->right;
    }

    //cout << "got to the end" << endl;
    pointer->right = insert;
    insert->parent = pointer;

    // Follows bullet point 2 on page 14 of balanced tree ppt
    SetNodeColor(insert, RED);
}

// Goes down right side of tree and resets tree into a red-black tree.
// Called every time a node is inserted
void MerkleTree::RebalanceRedBlackTree(MerkleNode* node) {
    if (node->parent == nullptr || node->parent->parent == nullptr) {
        return;
    }
    
    while (GetNodeColor(node->parent) == RED) {
        // Check to see if tree is becoming like a linked list
        if (node->parent->parent->left == nullptr && node->parent->left == nullptr) {
            RotateLeft(node);

            // check if uncle is red or black
        } else if (GetNodeColor(node->parent->parent->left) == RED) {
            SetNodeColor(node->parent->parent->left, BLACK);
            SetNodeColor(node->parent, BLACK);
            // If grandparent is root we want it to be black 
            if (node->parent->parent == root_) {
                SetNodeColor(node->parent->parent, BLACK);
            } else {
                SetNodeColor(node->parent->parent, RED);
            }

            // Node + Grandparent are now the correct colors but that can lead
            // to other parts of the tree not following rb rules
            node = node->parent->parent;

        } else if (GetNodeColor(node->parent->left) == BLACK &&
                   GetNodeColor(node->left) == BLACK) {
            RotateLeft(node);
        }
    }
}

// Makes every merkle node a hash of its leaves. Only called when nodes created
// from driver populate all leaf nodes.
void MerkleTree::ReMerkle() {
	ReMerkleHelper(root_);
}

// Recursively goes over every node and makes the digest of the merkle nodes a
// hash of the leaf nodes
void MerkleTree::ReMerkleHelper(MerkleNode* node) {
    if (node->right == nullptr || node->left == nullptr) {
        return;
    }

    ReMerkleHelper(node->right);
    ReMerkleHelper(node->left);

    byte insertDigest[CryptoPP::SHA256::DIGESTSIZE];

    GetHash(insertDigest, node);

    memcpy_s(node->digest, 
             CryptoPP::SHA256::DIGESTSIZE, 
             insertDigest, 
             CryptoPP::SHA256::DIGESTSIZE);
}

// Replaces the byte array with the hash of the node's children
void MerkleTree::GetHash(byte* digest, MerkleNode* node) {
    string message = "";

    for (int i = 0; i < CryptoPP::SHA256::DIGESTSIZE; i++) {
        message += node->right->digest[i];
    }

    for (int i = 0; i < CryptoPP::SHA256::DIGESTSIZE; i++) {
        message += node->left->digest[i];
    }

    hash.CalculateDigest(digest, (byte*) message.c_str(), message.length());
}

// Rotates left around a node, keeps the RBTree coloring
void MerkleTree::RotateLeft(MerkleNode* node) {
    // Naming convention from slide "Balanced Trees" pg 14
    MerkleNode* x = node;
    MerkleNode* p = node->parent;
    MerkleNode* g = node->parent->parent;

    if (g == root_) {
        root_ = p;
    } else {
        p->parent = g->parent;
        g->parent->right = p;
    }

    if (p->left != nullptr) {
        g->right = p->left;
        p->left->parent = g;
    } else {
        g->right = nullptr;
    }

    p->left = g;
    g->parent = p;

    // Now that nodes are swapped we need to recolor
    SetNodeColor(p, BLACK);
    SetNodeColor(x, RED);
    SetNodeColor(g, RED);
}

// Find which struct and what bit color relates to this node's color
int MerkleTree::GetNodeColor(const MerkleNode* node) {
    int color_index = (node->key / (SCALING / 2)) / BITS_PER_BYTE;

    int bit_index = (node->key / (SCALING / 2)) % BITS_PER_BYTE;

    switch (bit_index) {
        case 0:
            return colors_[color_index].b0;

        case 1:
            return colors_[color_index].b1;

        case 2:
            return colors_[color_index].b2;

        case 3:
            return colors_[color_index].b3;

        case 4:
            return colors_[color_index].b4;

        case 5:
            return colors_[color_index].b5;

        case 6:
            return colors_[color_index].b6;

        case 7:
            return colors_[color_index].b7;

        default:
            cout << "This should not be reachable (GetNodeColor)" << endl;
            return -1;
    }
}

// Set which struct and bitstruct relates to this node's color
void MerkleTree::SetNodeColor(const MerkleNode* node, const int color) {
    // Find which struct and what bit relates to this node
    int color_index = (node->key / (SCALING / 2)) / BITS_PER_BYTE;

    int bit_index = (node->key / (SCALING / 2)) % BITS_PER_BYTE;

    switch (bit_index) {
        case 0:
            colors_[color_index].b0 = color;
            break;

        case 1:
            colors_[color_index].b1 = color;
            break;

        case 2:
            colors_[color_index].b2 = color;
            break;

        case 3:
            colors_[color_index].b3 = color;
            break;

        case 4:
            colors_[color_index].b4 = color;
            break;

        case 5:
            colors_[color_index].b5 = color;
            break;

        case 6:
            colors_[color_index].b6 = color;
            break;

        case 7:
            colors_[color_index].b7 = color;
            break;

        default:
            cout << "This should not be reachable (SetNodeColor) color:" << color_index << " bit: " << bit_index << endl;
    }
}
