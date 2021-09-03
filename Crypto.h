#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

// the PRF with HMAC-SHA256, the length of PRF_output should not be smaller than 32
int PRF(unsigned char* key,unsigned char* data,unsigned char* PRF_output,unsigned int length){
    if(strlen((char*)PRF_output)<length)                           // check if variable length is not larger than the length of PRF_output
        return -1;
    
    const EVP_MD* engine=EVP_sha256();                              // the HMAC engine is HMAC-SHA256
    HMAC_CTX* ctx=NULL;                                             // the context of HMAC
    unsigned char* buffer=(unsigned char*)malloc(EVP_MAX_MD_SIZE);  // the buffer with possible maximum size
    unsigned int mac_length=0;                                      // the size of actual output
    
    ctx=HMAC_CTX_new();
    HMAC_Init_ex(ctx,key,strlen((char *)key),engine,NULL);
    HMAC_Update(ctx,data,strlen((char *)data));
    HMAC_Final(ctx,buffer,&mac_length);
    memcpy(PRF_output,buffer,length);                               // Copy the output from the buffer
    free(buffer);
    return 0;
}

// the secure random string generator (0: success; -1: length verification error; -2: random error)
int randomString(unsigned char* randomString_output,unsigned int length){
    if(strlen((char *)randomString_output)<length)                 // check if variable length is not larger than the length of randomString_output
        return -1;
    
    int code=RAND_bytes(randomString_output,length);
    if (code!=1)
        return -2;
    
    return 0;
}