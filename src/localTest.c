#include <stdio.h>

#include "Query.h"
#include "TreeNode.h"

PlainElement plainElement[RECORDS_NUM];
unsigned char k1[HMAC_LENGTH];

TreeNode* tn;

void init(){
    srand(time(NULL));
    for(int i=0;i<RECORDS_NUM;i++){
        plainElement[i].id=i;
        for(int j=0;j<KEY_NUM;j++){
            plainElement[i].data[j]=i;         // the value range is from 0 to 499
        }
    }

    randomString(k1,HMAC_LENGTH);
    
    return;
}



int main(){
    int res[RECORDS_NUM];

    init();
    tn=buildTree(plainElement,0,RECORDS_NUM);
    PlainQuery plainQuery;

    srand(time(NULL));
    for(int i=0;i<KEY_NUM;i++){
        plainQuery.plainQueryKey[i].isSmaller=1;
        plainQuery.plainQueryKey[i].selKey=i;
        plainQuery.plainQueryKey[i].value=0;      // the value range is from 0 to 499;
    }

    Query* query=(Query*)malloc(sizeof(Query));
    encryptQuery(k1,&plainQuery,query);

    int isMatched[RECORDS_NUM];
    int ret=search(tn,query,res);

//    printCreated();
    
    for(int i=0;i<RECORDS_NUM;i++)
        isMatched[i]=0;

    for(int i=1;i<res[0];i++){
        isMatched[i]=1;
        printf("%d ",res[i]);
    }
    printf("\n");
    printf("%d\n",res[0]);

    return 0;
}