#include <stdio.h>

#include "Query.h"
#include "TreeNode.h"

PlainElement plainElement[6];
PlainQuery plainQuery;
unsigned char k1[HASH_LENGTH];

TreeNode* tn;
Query query;

void init(){
    plainElement[0].id=0;
    plainElement[0].data[0]=700;
    plainElement[0].data[1]=20;

    plainElement[1].id=1;
    plainElement[1].data[0]=900;
    plainElement[1].data[1]=60;
    
    plainElement[2].id=2;
    plainElement[2].data[0]=500;
    plainElement[2].data[1]=40;

    plainElement[3].id=3;
    plainElement[3].data[0]=800;
    plainElement[3].data[1]=55;

    plainElement[4].id=4;
    plainElement[4].data[0]=200;
    plainElement[4].data[1]=30;

    plainElement[5].id=5;
    plainElement[5].data[0]=400;
    plainElement[5].data[1]=50;

    randomString(k1,HASH_LENGTH);
    
    return;
}



int main(){
    init();
    tn=buildTree(plainElement,0,6);
    printf("%d\n",tn->leftPointer->id);
}