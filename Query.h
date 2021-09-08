#include "Params.h"
#include "Crypto.h"

// the query unit for one key
typedef struct {
    unsigned char blockCipher[INT_LENGTH/BLOCK_SIZE][HASH_LENGTH];   // Enc(key||op||value)
    unsigned char hashValue[HASH_LENGTH];                            // H_k(key||op)
} QueryKey;

// the query structure
typedef struct {
    QueryKey keys[KEY_NUM];
} Query;

// the plaintext query
typedef struct {
    short selKey;                                           // the target key ID
    unsigned char isSmaller;                                // if the operator is smaller
    unsigned int value;                                     // the corresponding value
} PlainQuery;

// to encrypt the query unit for one key (0: success; -1: hash error; -2: block token error)
int encryptForOneKey(unsigned char* k1,PlainQuery* plainQuery, QueryKey* queryKey){
    char dataBuf[INT_LENGTH+1],binValue[INT_LENGTH];        // dataBuf: to store the concatenated string, binValue: the binary representation of data value
    sprintf(dataBuf,"%d",plainQuery->selKey);               // transform the key ID to string
    if (plainQuery->isSmaller>0)                            // check if the operator is smaller
        strcat(dataBuf,"<");
    else
        strcat(dataBuf,">");
    char* dataString=(char *)malloc(strlen(dataBuf));
    memcpy(dataString,dataBuf,strlen(dataBuf));             // dataString: the valid part of dataBuf
    int ret=PRF(k1,(unsigned char*)dataString,queryKey->hashValue,HASH_LENGTH,strlen(dataBuf),HASH_LENGTH);
    free(dataString);
    if(ret !=0)
        return -1;
    
    bzero(binValue,INT_LENGTH);
    
    // to transform value into binary representation
    int i=INT_LENGTH-1;
    unsigned int dec=plainQuery->value;
    while(dec!=0){
        binValue[i--]=dec%2;
        dec/=2;
    }

    for(i=0;i<INT_LENGTH/BLOCK_SIZE;i++){                   // for each block
        bzero(dataBuf,INT_LENGTH+1);
        // to generate the token for this block
        sprintf(dataBuf,"%d",plainQuery->selKey);
        strncat(dataBuf,&binValue[i*BLOCK_SIZE],BLOCK_SIZE);
        if (plainQuery->isSmaller>0)
            strcat(dataBuf,"<");
        else
            strcat(dataBuf,">");
        char* dataString=(char *)malloc(strlen(dataBuf));
        memcpy(dataString,dataBuf,strlen(dataBuf));
        ret=PRF(k1,(unsigned char*)dataString,queryKey->blockCipher[i],HASH_LENGTH,strlen(dataBuf),HASH_LENGTH);
        free(dataString);
        if(ret !=0)
            return -2;
    }
    return 0;
}

// encrypt the whole query (for each key) (0: success; -1: query generation for one key error)
int encryptQuery(unsigned char* k,PlainQuery* plainQuery,Query* query){
    int ret;
    for(int i=0;i<KEY_NUM;i++){
        ret=encryptForOneKey(k,&plainQuery[i],&(query->keys[i]));
        if (ret!=0)
            return -1;
    }
    return 0;
}