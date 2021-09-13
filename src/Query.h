#ifndef QUERY_H
#define QUERY_H
#include "Params.h"
#include "Crypto.h"
#include "TreeNode.h"

// the query unit for one key
typedef struct {
    unsigned char blockCipher[INT_LENGTH/BLOCK_SIZE][HMAC_LENGTH];   // Enc(key||op||value)
    unsigned char hashValue[HMAC_LENGTH];                            // H_k(key||op)
} QueryKey;

// the query structure
typedef struct {
    QueryKey keys[KEY_NUM];
} Query;

// the plaintext query for one key
typedef struct {
    short selKey;                                           // the target key ID
    unsigned char isSmaller;                                // if the operator is smaller
    unsigned int value;                                     // the corresponding value
} PlainQueryKey;

typedef struct {
    PlainQueryKey plainQueryKey[KEY_NUM];
} PlainQuery;

int encryptQuery(unsigned char* k1,PlainQuery* plainQuery,Query* query);
int search(TreeNode* root, Query* query,int* result);

#endif /* QUERY_H */
