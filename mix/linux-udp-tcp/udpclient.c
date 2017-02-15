/**
*	@file: udpclient.c
*	@brief: A simple Udp server
*	@author: ToakMa <mchgloak1120@163.com>
*	@date:	2014/10/09
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFF_SIZE 1024
#define PORT	 9988

int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr_in remote_addr;
	int len;
	char buff[BUFF_SIZE];

	//1. create a socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == sockfd)
	{
		perror("udp client socket: ");
		return -1;
	}
	
	//2. prepare ip and port
	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port   = htons(PORT);
	remote_addr.sin_addr.s_addr = inet_addr(argv[1]);
	bzero(&(remote_addr.sin_zero), 8);
	
	//3. sendto
	strcpy(buff, "this a test\n");
	printf("sending : %s\n", buff);
	len = sendto(sockfd, buff, strlen(buff), 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	if (len < 0)
	{
		perror("udp client sendto :");
		return -1;
	}
	
	//4. close
	close(sockfd);

	return 0;
}
