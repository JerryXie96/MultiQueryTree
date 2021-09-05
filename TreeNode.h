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

// the partition function for quick sort
int partition(PlainElement* plainElementList, short selKeyThisLayer, int low, int high){
    PlainElement pivot=plainElementList[high];
    int i=low-1;

    for(int j=low;j<=high-1;j++){
        if(plainElementList[j].data[i]<pivot.data[i]){
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

// build the tree structure based on the plaintext element list
TreeNode* buildTree(PlainElement* plainElementList, short selKeyThisLayer){

}