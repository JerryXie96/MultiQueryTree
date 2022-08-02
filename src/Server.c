#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "TreeNode.h"
#include "Query.h"

typedef struct {
    int id;
    IndexKey indexKey[KEY_NUM];
    unsigned char gamma[GAMMA_LENGTH]; 
} ScannedIndex;

unsigned char k1[HMAC_LENGTH];                          // k1 key

PlainElement plainElement[RECORDS_NUM];                 // the plaintext records

TreeNode* root;                                         // the root node of index tree

ScannedIndex scannedIndex[RECORDS_NUM];

// init the basic parameters
void init(){
    int temp;
    FILE *key,*dataset;
    key=fopen("k1.key","r");       // read k1
    for(int i=0;i<HMAC_LENGTH;i++)
        fscanf(key,"%hhu",&k1[i]);

    dataset=fopen("LBMA.data","r");
    for(int i=0;i<RECORDS_NUM;i++){
        plainElement[i].id=i;
        for(int j=0;j<DATASET_KEY_NUM;j++){
            fscanf(dataset,"%d",&temp);
            if(j<KEY_NUM){
                plainElement[i].data[j]=temp;
            }
        }
    }

    fclose(key);
    fclose(dataset);
    return;
}

void build(){
    root=buildTree(plainElement,0,RECORDS_NUM);
    return;
}

void build_scan(){
    char dataBuf[SHA256_DIGEST_LENGTH+4+BLOCK_SIZE+1],binValue[INT_LENGTH],kBin[BLOCK_SIZE];
    unsigned char hmacBuf[HMAC_LENGTH];
    int curPos,t;

    for(int z=0;z<RECORDS_NUM;z++){
        PlainElement* median=&plainElement[z];
        ScannedIndex* tn=&scannedIndex[z];

        tn->id=z;
        randomString(tn->gamma,GAMMA_LENGTH);
        
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
                    bzero(dataBuf,SHA256_DIGEST_LENGTH+4+BLOCK_SIZE+1);
                    if(j>0)
                        sha256((unsigned char*)binValue,(unsigned char*)dataBuf,j*BLOCK_SIZE,SHA256_DIGEST_LENGTH);
                    if(k<t){
                        // the first four bytes after hash value is used to store the key id
                        dataBuf[SHA256_DIGEST_LENGTH+0]=(i>>24) & 0xFF;
                        dataBuf[SHA256_DIGEST_LENGTH+1]=(i>>16) & 0xFF;
                        dataBuf[SHA256_DIGEST_LENGTH+2]=(i>>8) & 0xFF;
                        dataBuf[SHA256_DIGEST_LENGTH+3]=i & 0xFF;
                    
                        bzero(kBin,BLOCK_SIZE);
                        int jk=BLOCK_SIZE-1;
                        unsigned int dec=k;
                        while(dec!=0){
                            kBin[jk--]=dec%2;
                            dec/=2;
                        }

                        memcpy(dataBuf+SHA256_DIGEST_LENGTH+4,kBin,BLOCK_SIZE);
                        dataBuf[SHA256_DIGEST_LENGTH+4+BLOCK_SIZE]='<';

                        PRF(k1,(unsigned char*)dataBuf,hmacBuf,HMAC_LENGTH,SHA256_DIGEST_LENGTH+4+BLOCK_SIZE+1,HMAC_LENGTH);
                        PRF(tn->gamma,hmacBuf,(tn->indexKey[i]).block[j].blockCipher[curPos++],GAMMA_LENGTH,HMAC_LENGTH,HMAC_LENGTH);
                    } else if (k>t){
                        // the first four bytes is used to store the key id
                        dataBuf[SHA256_DIGEST_LENGTH+0]= (i>>24) &0xFF;
                        dataBuf[SHA256_DIGEST_LENGTH+1]= (i>>16) &0xFF;
                        dataBuf[SHA256_DIGEST_LENGTH+2]= (i>>8) &0xFF;
                        dataBuf[SHA256_DIGEST_LENGTH+3]= i &0xFF;

                        bzero(kBin,BLOCK_SIZE);
                        int jk=BLOCK_SIZE-1;
                        unsigned int dec=k;
                        while(dec!=0){
                            kBin[jk--]=dec%2;
                            dec/=2;
                        }

                        memcpy(dataBuf+SHA256_DIGEST_LENGTH+4,kBin,BLOCK_SIZE);
                        dataBuf[SHA256_DIGEST_LENGTH+4+BLOCK_SIZE]='>';

                        PRF(k1,(unsigned char*)dataBuf,hmacBuf,HMAC_LENGTH,SHA256_DIGEST_LENGTH+4+BLOCK_SIZE+1,HMAC_LENGTH);
                        PRF(tn->gamma,hmacBuf,(tn->indexKey[i]).block[j].blockCipher[curPos++],GAMMA_LENGTH, HMAC_LENGTH,HMAC_LENGTH);
                    } else                                              // k=t: do nothing
                        continue;
                }
            }
        
        }
    }
}

void server_search(int clientfd){
    struct timespec begin,end;
    double res_time=0.0;
    for(int i=0;i<12;i++){
        unsigned char* queryBin=(unsigned char*)malloc(sizeof(Query));
        Query* query=NULL;
        int len;
        int res[RECORDS_NUM+1];

        // printf("Data receiving.\n");
        len=recv(clientfd,queryBin,sizeof(Query),MSG_WAITALL);
        if(len<sizeof(Query)){
            fprintf(stderr,"Recv data error!\n");
            return;
        }
        // printf("Data received.\n");

        query=(Query *)queryBin;
        // printf("Searching.\n");
        clock_gettime(CLOCK_REALTIME, &begin);
        int searchLen=search(root,query,res);
        // printf("Search successfully.\n");
        clock_gettime(CLOCK_REALTIME, &end);
        long sec = end.tv_sec - begin.tv_sec;
        long nsec = end.tv_nsec - begin.tv_nsec;
        double elapsed = sec + nsec * 1e-9;
        if (i >= 2)
            res_time += elapsed * 1000;
        
        len=send(clientfd,res,(RECORDS_NUM+1)*sizeof(int),0);
        if(len<(RECORDS_NUM+1)*sizeof(int)){
            fprintf(stderr,"Send error!\n");
            return;
        }

        printf("%d: length=%d res_length=%d query_size=%ld\n",i,res[0],searchLen-1,sizeof(Query));
        free(queryBin);
    }
    printf("Server Time Cost: %.6lf ms\n",res_time/10);
    return;
}

// check if this scannedIndex (tn) is matched for the selKey with query (1: matched; 0: not matched)
int isMatched_scanned(ScannedIndex* tn, short selKey, Query* query){
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

void server_search_scanned(int clientfd){
    struct timespec begin,end;
    double res_time=0.0;
    for(int i=0;i<12;i++){
        unsigned char* queryBin=(unsigned char*)malloc(sizeof(Query));
        Query* query=NULL;
        int len;
        int res[RECORDS_NUM+1];

        // printf("Data receiving.\n");
        len=recv(clientfd,queryBin,sizeof(Query),MSG_WAITALL);
        if(len<sizeof(Query)){
            fprintf(stderr,"Recv data error!\n");
            return;
        }
        // printf("Data received.\n");

        query=(Query *)queryBin;
        // printf("Searching.\n");
        clock_gettime(CLOCK_REALTIME, &begin);
        int searchLen=0;
        for(int j=0;j<RECORDS_NUM;j++){
            int isMatched_ind=1;
            for(int k=0;k<KEY_NUM;k++){
                isMatched_ind=isMatched_scanned(&scannedIndex[j],k,query);
                if(!isMatched_ind)
                    break;
            }
            if(!isMatched_ind)
                continue;
            res[++searchLen]=j;
        }
        res[0]=searchLen;
        // printf("Search successfully.\n");
        clock_gettime(CLOCK_REALTIME, &end);
        long sec = end.tv_sec - begin.tv_sec;
        long nsec = end.tv_nsec - begin.tv_nsec;
        double elapsed = sec + nsec * 1e-9;
        if (i >= 2)
            res_time += elapsed * 1000;
        
        len=send(clientfd,res,(RECORDS_NUM+1)*sizeof(int),0);
        if(len<(RECORDS_NUM+1)*sizeof(int)){
            fprintf(stderr,"Send error!\n");
            return;
        }

        printf("%d: length=%d res_length=%d query_size=%ld\n",i,res[0],searchLen-1,sizeof(Query));
        free(queryBin);
    }
    printf("Server Time Cost: %.6lf ms\n",res_time/10);
    return;
}

int main(int argc, char *argv[]){
    int sockfd,clientfd;
    struct sockaddr_in server_addr,client_addr;
    size_t client_addr_size;

    // check the arguments
    if (argc!=2){
        fprintf(stderr, "Please provide enough arguments! Format: Server [port]\n");
        return -1;
    }

    printf("Initing.\n");
    init();

    sockfd=socket(AF_INET,SOCK_STREAM,0);
    if(sockfd==-1) {
        fprintf(stderr, "Create socket error!\n");
        return -1;
    }
    printf("Socket created.\n");

    server_addr.sin_family=AF_INET;
    server_addr.sin_addr.s_addr=INADDR_ANY;
    server_addr.sin_port=htons(atoi(argv[1]));

    if(bind(sockfd,(struct sockaddr *)&server_addr,sizeof(server_addr))<0){
        fprintf(stderr,"Bind error!\n");
        return -1;
    }
    printf("Bind successfully.\n");

    printf("Index Building.\n");
    build();
    // build_scan();

    listen(sockfd,3);
    printf("Wait for the connection.\n");

    client_addr_size=sizeof(struct sockaddr_in);
    clientfd=accept(sockfd,(struct sockaddr *)&client_addr,(socklen_t *)&client_addr_size);
    if(clientfd<0){
        fprintf(stderr,"Accept error!\n");
        return -1;
    }
    printf("Connection Accepted.\n");

    server_search(clientfd);
    // server_search_scanned(clientfd);

    return 0;
}
