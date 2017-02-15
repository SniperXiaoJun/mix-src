#include<sys/types.h>
#include<sys/socket.h>
#include<strings.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<errno.h>
#include<signal.h>
#include<sys/wait.h>
#include<pthread.h> 

extern int hsm_encrypt_pin(char *sBrhId, char *sFlag, char *sPinText, char *sPan, char *sPik, char *sPinBlk);

char * file_log = "server.log";

void FILE_LOG_STRING(char * fileName, char * cstring)
{
    FILE * file = fopen(fileName, "a+");

    fwrite(cstring,strlen(cstring), 1, file);
	fwrite("\n",1,1,file);
        
    fclose(file);
}

void FILE_LOG_NUMBER(char * fileName, int number)
{
    FILE * file = fopen(fileName, "a+");
	
	char data[20] = {0};

	sprintf(data, "%08x", number);

    fwrite(data, strlen(data),1, file);
	fwrite("\n",1,1,file);
        
    fclose(file);
}


#define LISTEN_PORT 8484
void str_echo(int sockfd)
{
    ssize_t n;
    char line[512];

    printf("ready to read\n");
    while( (n=read(sockfd,line,512))>0 )
    {
        char sBrhId[21] = {0};
        char sFlag[2]={0};
        char sPinText[17]={0};
        char sPan[51]={0};
        char sPik[49]={0};
        char sPinBlk[35]={0};
      	char s2Client[40]={0};
        int iRet = 0;
            
        line[n]='\0';

        memcpy(sBrhId, "nbank",strlen("nbank"));
        memcpy(sFlag, "R",1);
        memcpy(sPinText,"06",2);
        memcpy(sPinText + 2, line,  6);
        memcpy(sPinText + 8, "FFFFFFFF", 8);
        memcpy(sPik, "", 0);
				memcpy(sPan, line+6, strlen(line+6));

        iRet = hsm_encrypt_pin(sBrhId, sFlag, sPinText, sPan, NULL, sPinBlk);
        
        FILE_LOG_STRING(file_log,"iRet=");
        FILE_LOG_NUMBER(file_log,iRet);
        
        if(iRet == 0)
        {
        	memcpy(s2Client,"0:",2);
        	memcpy(s2Client + 2,sPinBlk,strlen(sPinBlk));		
        }
        else
        {
        	memcpy(s2Client,"1:",2);
        	memcpy(s2Client + 2,sPinBlk,strlen(sPinBlk));	
        }
    
				FILE_LOG_STRING(file_log,"Client2Server");
				FILE_LOG_STRING(file_log,line);
				FILE_LOG_STRING(file_log,"Server2Client");
				FILE_LOG_STRING(file_log,s2Client);
	
				write(sockfd,sPinBlk,strlen(s2Client));
        bzero(&line,sizeof(line));
    }
    printf("end read\n");

    close(sockfd);
}


void *run(void *arg)//thread execute function  
{  
    int sockfd = (int)arg;  
    ssize_t n;
    char line[512];

    printf("ready to read\n");
    while( (n=read(sockfd,line,512))>0 )
    {
        char sBrhId[21] = {0};
        char sFlag[2]={0};
        char sPinText[17]={0};
        char sPan[51]={0};
        char sPik[49]={0};
        char sPinBlk[35]={0};
      	char s2Client[40]={0};
        int iRet = 0;
            
        line[n]='\0';

        memcpy(sBrhId, "nbank",strlen("nbank"));
        memcpy(sFlag, "R",1);
        memcpy(sPinText,"06",2);
        memcpy(sPinText + 2, line,  6);
        memcpy(sPinText + 8, "FFFFFFFF", 8);
        memcpy(sPik, "", 0);
				memcpy(sPan, line+6, strlen(line+6));

        iRet = hsm_encrypt_pin(sBrhId, sFlag, sPinText, sPan, NULL, sPinBlk);
        
        FILE_LOG_STRING(file_log,"iRet=");
        FILE_LOG_NUMBER(file_log,iRet);
        
        if(iRet == 0)
        {
        	memcpy(s2Client,"0:",2);
        	memcpy(s2Client + 2,sPinBlk,strlen(sPinBlk));		
        }
        else
        {
        	memcpy(s2Client,"1:",2);
        	memcpy(s2Client + 2,sPinBlk,strlen(sPinBlk));	
        }
    
				FILE_LOG_STRING(file_log,"Client2Server");
				FILE_LOG_STRING(file_log,line);
				FILE_LOG_STRING(file_log,"Server2Client");
				FILE_LOG_STRING(file_log,s2Client);
	
				write(sockfd,sPinBlk,strlen(s2Client));
        bzero(&line,sizeof(line));
    }
    printf("end read\n");
    close(sockfd);
    return NULL;  
}


int main(int argc, char **argv)
{
    int listenfd, connfd;
    pid_t childpid;
    socklen_t chilen;
    pthread_t tid;

    struct sockaddr_in chiaddr,servaddr;

    listenfd=socket(AF_INET,SOCK_STREAM,0);
    if(listenfd==-1)
    {
        printf("socket established error: %s\n",(char*)strerror(errno)); return -1;
    }

    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family=AF_INET;
    servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    servaddr.sin_port=htons(LISTEN_PORT);

    int bindc=bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
    if(bindc==-1)
    {
        printf("bind error: %s\n",strerror(errno)); return -1;
    }

    listen(listenfd,2000);
    for(;;)
    {
        chilen=sizeof(chiaddr);

        connfd=accept(listenfd,(struct sockaddr*)&chiaddr,&chilen);
        if(connfd==-1)
        {    printf("accept client error: %s\n",strerror(errno)); return -1; }
        else        
            printf("client connected\n");

				/*
        if((childpid=fork())==0)
        {
            close(listenfd);
            printf("client from %s\n",inet_ntoa(chiaddr.sin_addr));
            str_echo(connfd);
            exit(0);    
        }
        else if (childpid<0)
            printf("fork error: %s\n",strerror(errno));
        */
        
        printf("client from %s\n",inet_ntoa(chiaddr.sin_addr));
        //create new thread handle client  
        pthread_create(&tid,NULL,run,(void *)connfd);  
        pthread_detach(tid); 
        
        //close(connfd);
    }
}
