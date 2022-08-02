#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "TreeNode.h"
#include "Query.h"

unsigned char k1[HMAC_LENGTH];                          // k1 key

PlainElement plainElement[RECORDS_NUM];                 // the plaintext records

int range[KEY_NUM][2];                                  // 0 is min, and 1 is max


// init the basic parameter
void init(){
    int temp;
    FILE *key,*dataset;

    for(int i=0;i<KEY_NUM;i++){
        range[i][0]=INT_MAX;
        range[i][1]=0;
    }

    key=fopen("k1.key","r");
    for(int i=0;i<HMAC_LENGTH;i++)
        fscanf(key,"%hhu",&k1[i]);

    dataset=fopen("LBMA.data","r");
    for(int i=0;i<RECORDS_NUM;i++){
        plainElement[i].id=i;
        for(int j=0;j<DATASET_KEY_NUM;j++){
            fscanf(dataset,"%d",&temp);
            if(j<KEY_NUM){
                plainElement[i].data[j]=temp;
                if(temp<range[j][0])
                        range[j][0]=temp;
                if(temp>range[j][1])
                        range[j][1]=temp;
            }
        }
    }

    fclose(key);
    fclose(dataset);
    return;
}

void client_query(int sockfd){
    struct timespec begin,end;
    double res_time=0.0;

    srand(time(NULL));
    for(int i=0;i<12;i++){
        PlainQuery plainQuery;
        Query query;
        int res[RECORDS_NUM+1],selected_id;

        selected_id=rand()%RECORDS_NUM;
        for(int i=0;i<KEY_NUM;i++){
            plainQuery.plainQueryKey[i].isSmaller=1;
            plainQuery.plainQueryKey[i].selKey=i;
            if(i==0)
                plainQuery.plainQueryKey[i].value=range[i][0]+(int)(0.4*(range[i][1]-range[i][0])); 
            if(i==1)
                plainQuery.plainQueryKey[i].value=range[i][0]+(int)(0.4*(range[i][1]-range[i][0])); 
            if(i==2)
                plainQuery.plainQueryKey[i].value=range[i][0]+(int)(0.4*(range[i][1]-range[i][0])); 
            if(i==3)
                plainQuery.plainQueryKey[i].value=range[i][0]+(int)(0.4*(range[i][1]-range[i][0])); 
        }

        clock_gettime(CLOCK_REALTIME, &begin);
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
        clock_gettime(CLOCK_REALTIME, &end);
        long sec = end.tv_sec - begin.tv_sec;
        long nsec = end.tv_nsec - begin.tv_nsec;
        double elapsed = sec + nsec * 1e-9;
        if (i >= 2)
            res_time += elapsed * 1000;
        
        printf("Queried: %d result_size=%d\n",i,res[0]);
    }
    printf("Client Time Cost: %.6lf ms\n",res_time/10);
    return;
}

int main(int argc, char *argv[]){
    int sockfd;
    struct sockaddr_in server_addr;

    printf("Initing.\n");
    init();

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
