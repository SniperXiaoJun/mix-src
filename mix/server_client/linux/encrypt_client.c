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
#include <string.h>


#define MAXLINE 2000

#define PORT 8484

char * ip = "198.1.1.187";


int main()
{
	int sockfd;
	struct sockaddr_in  servaddr;
	
	char buffer[MAXLINE] = {0};
	
	int readlen = 0;
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
	
	connect(sockfd, (struct sockaddr*)&servaddr, sizeof(struct sockaddr));
	
	write(sockfd, "0000006222000502101347804", strlen("0000006222000502101347804"));

	readlen = read(sockfd,buffer, MAXLINE);
	
	printf("%s", buffer);

	return 0;
}



