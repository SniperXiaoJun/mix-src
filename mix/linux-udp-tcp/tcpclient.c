/**
*	@file: tcpclient.c
*	@brief: A simple Tcp client
*	@author: ToakMa <mchgloak1120@163.com>
*	@date: 2014/10/09
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define PORT 9000
#define BUFF_SIZE 1024

int main(int argc, char *argv[])
{
	int sockfd;
	int recv_len, send_len;
	struct sockaddr_in remote_addr;
	char buff[BUFF_SIZE];
	int res;

	//1. create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == sockfd)
	{
		perror("client socket :");
		return -1;
	}
	
	//2. prepare ip and port
	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port   = htons(PORT);
	//remote_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	remote_addr.sin_addr.s_addr = inet_addr(argv[1]);
	bzero(&(remote_addr.sin_zero), 8);

	//3. connect to server
	res = connect(sockfd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	if (-1 == res)
	{
		perror("client connect: ");
		return -1;
	}
	printf("client connect server succ!\n");
	
	//4. recv sth
	recv_len = recv(sockfd, buff, sizeof(buff), 0);
	buff[recv_len] = '\0';
	printf(" %s ", buff);

	//5. interactive
	while (1)
	{
		printf("Enter string to send: ");
		scanf("%s", buff);
		if (!strcmp(buff, "quit"))
			break;
		
		send_len = send(sockfd, buff, strlen(buff), 0);
		recv_len = recv(sockfd, buff, BUFF_SIZE, 0);
		buff[recv_len] = '\0';
		printf("    received: %s \n", buff);
	}

	//6. close
	close(sockfd);

	return 0;
}

