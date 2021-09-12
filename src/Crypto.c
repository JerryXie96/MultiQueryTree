#include "Crypto.h"

// the PRF with HMAC-SHA256, the length of PRF_output should not be smaller than 32
int PRF(unsigned char* key,unsigned char* data,unsigned char* PRF_output, size_t key_len, size_t data_len, size_t output_len){
    const EVP_MD* engine=EVP_sha256();                              // the HMAC engine is HMAC-SHA256
    HMAC_CTX* ctx=NULL;                                             // the context of HMAC
    unsigned char buffer[EVP_MAX_MD_SIZE];  // the buffer with possible maximum size
    unsigned int mac_length=0;                                      // the size of actual output
    
    ctx=HMAC_CTX_new();
    HMAC_Init_ex(ctx,key,key_len,engine,NULL);
    HMAC_Update(ctx,data,data_len);
    HMAC_Final(ctx,buffer,&mac_length);
    memcpy(PRF_output,buffer,output_len);                               // Copy the output from the buffer
    return 0;
}

// the hash function based on SHA256 (0: success; -1: length error)
int sha256(unsigned char* data, unsigned char* output, size_t data_len, size_t output_len){
    // check the length of output_len, if smaller, return -1
    if(output_len<SHA256_DIGEST_LENGTH)
        return -1;

    SHA256_CTX ctx;
    unsigned char buffer[SHA256_DIGEST_LENGTH];

    SHA256_Init(&ctx);
    SHA256_Update(&ctx,data,data_len);
    SHA256_Final(buffer,&ctx);
    memcpy(output,buffer,SHA256_DIGEST_LENGTH);
    return 0;
}

// the secure random string generator (0: success; -1: random error)
int randomString(unsigned char* randomString_output,size_t output_len){
    int code=RAND_bytes(randomString_output,output_len);
    if (code!=1)
        return -1;
    return 0;
}