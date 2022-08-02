#include <stdio.h>
#include <openssl/rand.h>

#include "Params.h"

unsigned char k1[HMAC_LENGTH];

int main(){
    FILE *key;

    key=fopen("k1.key","w");
    RAND_bytes(k1,HMAC_LENGTH);
    for(int i=0;i<HMAC_LENGTH;i++)
        fprintf(key,"%hhu ",k1[i]);
    fclose(key);

    return 0;
}