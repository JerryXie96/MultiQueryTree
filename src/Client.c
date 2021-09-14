#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "TreeNode.h"
#include "Query.h"

unsigned char k1[HMAC_LENGTH];                          // k1 key

// init the basic parameter
void init(){
    FILE *in=fopen("k1.key","r");
    for(int i=0;i<HMAC_LENGTH;i++)
        fscanf(in,"%hhu",&k1[i]);

    return;
}

void client_query(int sockfd){
    PlainQuery plainQuery;
    Query query;
    int res[RECORDS_NUM+1];

    srand(time(NULL));
    for(int i=0;i<KEY_NUM;i++){
        plainQuery.plainQueryKey[i].isSmaller=rand()%2;
        plainQuery.plainQueryKey[i].selKey=i;
        plainQuery.plainQueryKey[i].value=rand()%200;      // the value range is from 0 to 199;
    }

    encryptQuery(k1,&plainQuery,&query);

    int len=send(sockfd,&query,sizeof(Query),0);
    if(len!=sizeof(Query)){
        fprintf(stderr,"Query send error!\n");
        return;
    }

    len=recv(sockfd,res,(RECORDS_NUM+1)*sizeof(int),MSG_WAITALL);
    if(len<(RECORDS_NUM+1)*sizeof(int)){
        fprintf(stderr,"Result recv error!\n");
        return;
    }
    for(int i=1;i<=res[0];i++)
        printf("%d ",res[i]);
    printf("\n");
    return;
}

int main(int argc, char *argv[]){
    int sockfd;
    struct sockaddr_in server_addr;

    // check the arguments
    if(argc!=3){
        fprintf(stderr, "Please provide enough arguments! Format: Client [ip] [port]\n");
        return -1;
    }

    if((sockfd=socket(AF_INET,SOCK_STREAM,0))<0){
        fprintf(stderr,"Create socket error\n");
        return -1;
    }
    printf("Socket created.\n");

    if(inet_pton(AF_INET,argv[1],&server_addr.sin_addr)<=0){
        fprintf(stderr,"inet_pton error!\n");
        return -1;
    }
    server_addr.sin_family=AF_INET;
    server_addr.sin_port=htons(atoi(argv[2]));

    printf("Connecting.\n");
    if(connect(sockfd,(struct sockaddr*)&server_addr,sizeof(server_addr))<0){
        fprintf(stderr,"Connection error!\n");
        return -1;
    }

    printf("Querying.\n");
    client_query(sockfd);

    return 0;
}
