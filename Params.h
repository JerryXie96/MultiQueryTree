#ifndef PARAMS_H
#define PARAMS_H
    
#define INT_LENGTH 32                               // the length of one integer (i.e., data)
#define BLOCK_SIZE 2                                // the length of one block in tokens and indexes
#define KEY_NUM 2                                   // the number of keys for one item
#define HASH_LENGTH 32                              // the length of hash value
#define GAMMA_LENGTH 4                              // the length of gamma
#define BLOCK_CIPHER_NUM ((1<<BLOCK_SIZE)-1)        // the number of ciphers in one index block
#endif  /* PARAMS_H */