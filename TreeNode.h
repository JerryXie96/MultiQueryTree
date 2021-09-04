#include "Params.h"

// the structure of one block in the index
typedef struct {
    unsigned char blockCipher[BLOCK_CIPHER_NUM][HASH_LENGTH]; 
} Block;

// the structure of one key in the index
typedef struct {
    Block block[BLOCK_SIZE];
} IndexKey;

typedef struct TN {
    int id;                         // the id of this node
    short selKey;                   // the index of selected key 
    IndexKey indexKey[KEY_NUM];     // the indexes for all keys for one tree node

    TN* leftPointer;                // the pointer of its left son
    TN* rightPointer;               // the pointer of its right son
} TreeNode;

// the structure of plaintext data element
typedef struct {
    int id;                         // the id of this element
    unsigned int data[KEY_NUM];     // the data for all the keys in this element
} PlainElement;