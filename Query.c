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

// check if this treenode (tn) is matched for the selKey with query (1: matched; 0: not matched)
int isMatched(TreeNode* tn, short selKey, Query* query){
    char isMatched=0;
    for(int i=0;i<INT_LENGTH/BLOCK_SIZE;i++){
        for(int j=0;j<3;j++){
            if(!memcmp((tn->indexKey[selKey]).block[i].blockCipher[j],(query->keys[selKey]).blockCipher[i],HASH_LENGTH)){
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
    TreeNode* tn;
    push(root);
    while(!isEmpty()){
        tn=pop();
        if(tn==NULL){
            printf(stderr,"error: empty stack\n");
            return -1;
        }
        isAllMatched=1;
        // check the ciphertext for selKey
        if(isMatched(tn,tn->selKey,query)){
            push(tn->leftPointer);
            push(tn->rightPointer);
        } else {                                // not matched, choose the direction for the next step
            isAllMatched=0;
            unsigned char* hash_result=(unsigned char*)malloc(HASH_LENGTH);
            PRF(tn->gamma,query->keys[tn->selKey],hash_result,HASH_LENGTH,HASH_LENGTH,HASH_LENGTH);
            if(!memcmp(tn->ptrLeft,hash_result,HASH_LENGTH))
                push(tn->leftPointer);
            if(!memcmp(tn->ptrRight,hash_result,HASH_LENGTH))
                push(tn->rightPointer);
            free(hash_result);
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
    return 0;
}
