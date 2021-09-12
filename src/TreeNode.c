#include "TreeNode.h"

// the partition function for quick sort
int partition(PlainElement* plainElementList, short selKeyThisLayer, int low, int high){
    PlainElement pivot=plainElementList[high];
    int i=low-1;

    for(int j=low;j<=high-1;j++){
        if(plainElementList[j].data[selKeyThisLayer]<pivot.data[selKeyThisLayer]){
            i++;
            PlainElement t=plainElementList[i];
            plainElementList[i]=plainElementList[j];
            plainElementList[j]=t;
        }
    }
    PlainElement t=plainElementList[i+1];
    plainElementList[i+1]=plainElementList[high];
    plainElementList[high]=t;
    return i+1;
}

// quick sort function to sort the plaintext element list according to the key selKeyThisLayer
void quickSort(PlainElement* plainElementList, short selKeyThisLayer, int low, int high){
    if(low<high){
        int p=partition(plainElementList,selKeyThisLayer,low,high);

        quickSort(plainElementList,selKeyThisLayer,low,p-1);
        quickSort(plainElementList,selKeyThisLayer,p+1,high);
    }
    return;
}

// transform bit string to decimal value
int binToDec(char* binArray, size_t len){
    int res=0, w=1;
    for(int i=len-1;i>=0;i--){
        res+=binArray[i]*w;
        w*=2;
    }
    return res;
}

// build the tree structure based on the plaintext element list
TreeNode* buildTree(PlainElement* plainElementList, short selKeyThisLayer, int length){
    char dataBuf[4+BLOCK_SIZE+1],binValue[INT_LENGTH],kBin[BLOCK_SIZE];
    int curPos,t;
    
    if(length<=0)
        return NULL;

    quickSort(plainElementList,selKeyThisLayer,0,length-1);

    PlainElement* median=&plainElementList[length/2];

    TreeNode* tn=(TreeNode*)malloc(sizeof(TreeNode));
    tn->id=median->id;
    tn->selKey=selKeyThisLayer;
    
    // generate the ciphertext for each key in tn
    for(int i=0;i<KEY_NUM;i++){
        bzero(binValue,INT_LENGTH);
        // to transform value into binary representation
        int j=INT_LENGTH-1;
        unsigned int dec=median->data[i];
        while(dec!=0){
            binValue[j--]=dec%2;
            dec/=2;
        }
        
        // generate the ciphertext for each block
        for(j=0;j<INT_LENGTH/BLOCK_SIZE;j++){
            curPos=0;                                               // the current pointer for the ciphertext in one block
            t=binToDec(&binValue[j*BLOCK_SIZE],BLOCK_SIZE);         // transform the binary value to decimal value based on BLOCK_SIZE
            for(int k=0;k<BLOCK_CIPHER_NUM+1;k++){                  // for each possible value
                bzero(dataBuf,4+BLOCK_SIZE+1);
                if(k<t){
                    // the first four bytes is used to store the key id
                    dataBuf[0]=(i>>24) & 0xFF;
                    dataBuf[1]=(i>>16) & 0xFF;
                    dataBuf[2]=(i>>8) & 0xFF;
                    dataBuf[3]=i & 0xFF;
                    
                    bzero(kBin,BLOCK_SIZE);
                    int jk=BLOCK_SIZE-1;
                    unsigned int dec=k;
                    while(dec!=0){
                        kBin[jk--]=dec%2;
                        dec/=2;
                    }

                    memcpy(dataBuf+4,kBin,BLOCK_SIZE);
                    dataBuf[4+BLOCK_SIZE]='<';

                    PRF(k1,(unsigned char*)dataBuf,(tn->indexKey[i]).block[j].blockCipher[curPos++],HASH_LENGTH,4+BLOCK_SIZE+1,HASH_LENGTH);
                } else if (k>t){
                    // the first four bytes is used to store the key id
                    dataBuf[0]= (i>>24) &0xFF;
                    dataBuf[1]= (i>>16) &0xFF;
                    dataBuf[2]= (i>>8) &0xFF;
                    dataBuf[3]= i &0xFF;

                    bzero(kBin,BLOCK_SIZE);
                    int jk=BLOCK_SIZE-1;
                    unsigned int dec=k;
                    while(dec!=0){
                        kBin[jk--]=dec%2;
                        dec/=2;
                    }

                    memcpy(dataBuf+4,kBin,BLOCK_SIZE);
                    dataBuf[4+BLOCK_SIZE]='>';
                    
                    PRF(k1,(unsigned char*)dataBuf,(tn->indexKey[i]).block[j].blockCipher[curPos++],HASH_LENGTH,4+BLOCK_SIZE+1,HASH_LENGTH);
                } else                                              // k=t: do nothing
                    continue;
            }
        }
        
    }

    randomString(tn->gamma,GAMMA_LENGTH);
    unsigned char ptr_smaller_inner[HASH_LENGTH];
    PRF(k1,(unsigned char*)"<",ptr_smaller_inner,HASH_LENGTH,strlen("<"),HASH_LENGTH);
    unsigned char ptr_smaller[HASH_LENGTH];
    PRF(tn->gamma,ptr_smaller_inner,ptr_smaller,GAMMA_LENGTH,HASH_LENGTH,HASH_LENGTH);

    unsigned char ptr_larger_inner[HASH_LENGTH];
    PRF(k1,(unsigned char*)">",ptr_larger_inner,HASH_LENGTH,strlen(">"),HASH_LENGTH);
    unsigned char ptr_larger[HASH_LENGTH];
    PRF(tn->gamma,ptr_larger_inner,ptr_larger,GAMMA_LENGTH,HASH_LENGTH,HASH_LENGTH);

    unsigned char ptr_concated[HASH_LENGTH*2];
    memcpy(ptr_concated,ptr_larger,HASH_LENGTH);
    memcpy(ptr_concated+HASH_LENGTH,ptr_smaller,HASH_LENGTH);
    unsigned char hash_to_deter[HASH_LENGTH];
    PRF(k1,(unsigned char*)ptr_concated,hash_to_deter,HASH_LENGTH,2*HASH_LENGTH,HASH_LENGTH);
    if(hash_to_deter[HASH_LENGTH*2-1]%2==0){
        memcpy(tn->ptrLeft,ptr_smaller,HASH_LENGTH);
        tn->leftPointer=buildTree(plainElementList,(selKeyThisLayer+1)%KEY_NUM,length/2);

        memcpy(tn->ptrRight,ptr_larger,HASH_LENGTH);
        tn->rightPointer=buildTree(plainElementList+(length/2+1),(selKeyThisLayer+1)%KEY_NUM,length/2-1);
    } else {
        memcpy(tn->ptrLeft,ptr_larger,HASH_LENGTH);
        tn->leftPointer=buildTree(plainElementList+(length/2+1),(selKeyThisLayer+1)%KEY_NUM,length/2-1);

        memcpy(tn->ptrRight,ptr_smaller,HASH_LENGTH);
        tn->rightPointer=buildTree(plainElementList,(selKeyThisLayer+1)%KEY_NUM,length/2);
    }
    
    
    return tn;
}
