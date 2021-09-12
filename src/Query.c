#include "Query.h"
#include "TreeNode.h"

TreeNode* stack[MAX_STACK];                                 // the stack for matching
int stackPtr=0;

// check if the stack is empty (1: is empty; 0: is not empty)
int isEmpty(){
    if(stackPtr==0)
        return 1;
    else
        return 0;
}

// push an item into the stack (0: success; -1: full stack)
int push(TreeNode* tn){
    if(stackPtr==MAX_STACK)
        return -1;
    stack[stackPtr++]=tn;
    return 0;
}

// pop an item from the stack (not NULL: success; NULL: empty stack)
TreeNode* pop(){
    if(stackPtr==0)
        return NULL;
    return stack[--stackPtr];
}

// to encrypt the query unit for one key (0: success; -1: hash error; -2: block token error)
int encryptForOneKey(unsigned char* k1,PlainQueryKey* plainQuery, QueryKey* queryKey){
    char dataBuf[SHA256_DIGEST_LENGTH+4+BLOCK_SIZE+1],binValue[INT_LENGTH];        // dataBuf: to store the concatenated string, binValue: the binary representation of data value

    if ((plainQuery->isSmaller)>0)                            // check if the operator is smaller
        PRF(k1,(unsigned char*)"<",queryKey->hashValue,HMAC_LENGTH,strlen("<"),HMAC_LENGTH);
    else
        PRF(k1,(unsigned char*)">",queryKey->hashValue,HMAC_LENGTH,strlen(">"),HMAC_LENGTH);
    

    // to transform value into binary representation
    int i=INT_LENGTH-1;
    unsigned int dec=plainQuery->value;
    bzero(binValue,INT_LENGTH);
    while(dec!=0){
        binValue[i--]=dec%2;
        dec/=2;
    }

    for(i=0;i<INT_LENGTH/BLOCK_SIZE;i++){                   // for each block
        // to generate the token for this block
        bzero(dataBuf,SHA256_DIGEST_LENGTH+4+BLOCK_SIZE+1);
        if(i>0)
            sha256(binValue,dataBuf,i*BLOCK_SIZE,SHA256_DIGEST_LENGTH);
        // the first four bytes is used to store the selKey
        dataBuf[SHA256_DIGEST_LENGTH+0]=((plainQuery->selKey)>>24) & 0xFF;
        dataBuf[SHA256_DIGEST_LENGTH+1]=((plainQuery->selKey)>>16) & 0xFF;
        dataBuf[SHA256_DIGEST_LENGTH+2]=((plainQuery->selKey)>>8) & 0xFF;
        dataBuf[SHA256_DIGEST_LENGTH+3]=(plainQuery->selKey) & 0xFF;
        
        memcpy(dataBuf+SHA256_DIGEST_LENGTH+4,&binValue[i*BLOCK_SIZE],BLOCK_SIZE);
        if ((plainQuery->isSmaller)>0)
            dataBuf[SHA256_DIGEST_LENGTH+4+BLOCK_SIZE]='<';
        else
            dataBuf[SHA256_DIGEST_LENGTH+4+BLOCK_SIZE]='>';

        PRF(k1,(unsigned char*)dataBuf,queryKey->blockCipher[i],HMAC_LENGTH,SHA256_DIGEST_LENGTH+4+BLOCK_SIZE+1,HMAC_LENGTH);
    }
    return 0;
}

// encrypt the whole query (for each key) (0: success; -1: query generation for one key error)
int encryptQuery(unsigned char* k1,PlainQuery* plainQuery,Query* query){
    int ret;
    for(int i=0;i<KEY_NUM;i++){
        ret=encryptForOneKey(k1,&(plainQuery->plainQueryKey[i]),&(query->keys[i]));
        if (ret!=0)
            return -1;
    }
    return 0;
}

// check if this treenode (tn) is matched for the selKey with query (1: matched; 0: not matched)
int isMatched(TreeNode* tn, short selKey, Query* query){
    unsigned char hmacBuf[HMAC_LENGTH];
    int isMatched=0;
        
    for(int i=0;i<INT_LENGTH/BLOCK_SIZE;i++){
        PRF(tn->gamma,(query->keys[selKey]).blockCipher[i],hmacBuf,GAMMA_LENGTH,HMAC_LENGTH,HMAC_LENGTH);
        for(int j=0;j<BLOCK_CIPHER_NUM;j++){
            if(!memcmp((tn->indexKey[selKey]).block[i].blockCipher[j],hmacBuf,HMAC_LENGTH)){
                isMatched=1;
                break;
            }
        }
        if(isMatched)
            break;
    }

    return isMatched;
}

// search the tree (result: the list of the matched IDs)
int search(TreeNode* root, Query* query,int* result){
    int i,isAllMatched,resPtr=0;
    unsigned char hash_result[HMAC_LENGTH];
    TreeNode* tn;
    push(root);
    while(!isEmpty()){
        tn=pop();
        isAllMatched=1;
        // check the ciphertext for selKey
        if(isMatched(tn,tn->selKey,query)){
            if(tn->leftPointer!=NULL)
                push(tn->leftPointer);
            if(tn->rightPointer!=NULL)
                push(tn->rightPointer);
        } else {                                // not matched, choose the direction for the next step
            isAllMatched=0;
            PRF(tn->gamma,(query->keys[tn->selKey]).hashValue,hash_result,GAMMA_LENGTH,HMAC_LENGTH,HMAC_LENGTH);
            if(tn->leftPointer!=NULL && !memcmp(tn->ptrLeft,hash_result,HMAC_LENGTH))
                push(tn->leftPointer);
            if(tn->rightPointer!=NULL && !memcmp(tn->ptrRight,hash_result,HMAC_LENGTH))
                push(tn->rightPointer);
        }

        // if the ciphertext for selKey is not matched, it is impossible that all the ciphertexts are matched for tn
        if(!isAllMatched)
            continue;
        // if the ciphertext for selKey is matched, check other ciphertexts
        for(i=0;isAllMatched && i<KEY_NUM;i++){
            if(i==tn->selKey)
                continue;
            isAllMatched=isMatched(tn,i,query);
        }

        // if all the ciphertexts are matched, add it to the result list
        if(isAllMatched)
            result[resPtr++]=tn->id;
    }
    return resPtr;
}
