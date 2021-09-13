#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "TreeNode.h"
#include "Query.h"

unsigned char k1[HMAC_LENGTH];                          // k1 key

PlainElement plainElement[RECORDS_NUM];                 // the plaintext records

TreeNode* root;                                         // the root node of index tree

// init the basic parameters
void init(){
    FILE *in=fopen("k1.key","r");       // read k1
    for(int i=0;i<HMAC_LENGTH;i++)
        fscanf(in,"%hhu",&k1[i]);

    srand(time(NULL));
    for(int i=0;i<RECORDS_NUM;i++){
        plainElement[i].id=i;
        for(int j=0;j<KEY_NUM;j++){
            plainElement[i].data[j]=rand()%500;         // the value range is from 0 to 499
        }
    }
    return;
}

void build(){
    root=buildTree(plainElement,0,RECORDS_NUM);
    return;
}

void server_search(int clientfd){
    unsigned char* queryBin=(unsigned char*)malloc(sizeof(Query));
    Query* query=NULL;
    int len;
    int res[RECORDS_NUM+1];

    printf("Data receiving.\n");
    len=recv(clientfd,queryBin,sizeof(Query),MSG_WAITALL);
    if(len<sizeof(Query)){
        fprintf(stderr,"Recv data error!\n");
        return;
    }
    printf("Data received.\n");

    query=(Query *)queryBin;
    printf("Searching.\n");
    search(root,query,res);
    printf("Search successfully.\n");

    len=send(clientfd,res,(RECORDS_NUM+1)*sizeof(int),0);
    if(len<(RECORDS_NUM+1)*sizeof(int)){
        fprintf(stderr,"Send error!\n");
        return;
    }

    free(queryBin);
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

    return 0;
}
