#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "Params.h"

int main(int argc, char *argv[]){
    // check the arguments
    if(argc!=3){
        fprintf(stderr, "Please provide enough arguments!\n");
        return -1;
    }

    // establish the TCP socket
    int sockfd,port;
    struct sockaddr_in servaddr;
    if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1){
        fprintf(stderr,"Socket Initialization Error!\n");
        return -1;
    }
    servaddr.sin_family=AF_INET;
    servaddr.sin_addr.s_addr=inet_addr(argv[1]);
    servaddr.sin_port=htons(atoi(argv[2]));
    if(connect(sockfd,&servaddr,sizeof(servaddr))!=0){
        fprintf(stderr,"Connection Failed!\n");
        return -1;
    }
    else
        printf("Connected.\n");

    return 0;
}
