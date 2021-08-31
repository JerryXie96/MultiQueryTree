#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "params.h"

int main(int argc, char *argv[]){
    // check the arguments
    if (argc!=2){
        fprintf(stderr, "Please provide enough arguments!\n");
        return -1;
    }

    // establish the TCP socket
    int sockfd,conn_fd,port;
    struct sockaddr_in servaddr,cliaddr;
    if ((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1){
        fprintf(stderr,"Socket Initialization Error!\n");
        return -1;
    }
    servaddr.sin_family=AF_INET;
    servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    servaddr.sin_port=htons(atoi(argv[1]));
    if((bind(sockfd,&servaddr,sizeof(servaddr)))!=0){
        fprintf(stderr,"Socket Bind Failed!\n");
        return -1;
    }
    if((listen(sockfd,5))!=0){
        fprintf(stderr,"Socket Listen Error!\n");
        return -1;
    } else 
        printf("Listening...\n");
    if((conn_fd=accept(sockfd,&cliaddr,sizeof(cliaddr)))<0){
        fprintf(stderr,"Accept Error!\n");
        return -1;
    } else 
        printf("Connection from Client Established.\n");

    return 0;
}