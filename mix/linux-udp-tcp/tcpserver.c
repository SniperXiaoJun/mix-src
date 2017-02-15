/**
*	@file:	tcpserver.c
*	@brief: A simple Tcp server
*	@author: ToakMa <mchgloak1120@163.com> 
*	@date:	2014/10/09
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

#define	PORT 9000
#define	WAIT_QUEUE_LEN 5
#define BUFF_SIZE 1024
#define WELCOME	"Welcome to my server ^_^!\n"

int main(int argc, char *argv[])
{
	int serverfd, clientfd;
	struct sockaddr_in saddr;
	struct sockaddr_in caddr;
	socklen_t c_addrlen;
	int res;
	int len;
	char buff[BUFF_SIZE];

	//1. create socket
	serverfd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == serverfd)
	{
		perror("server socket : ");
		return -1;
	}
	printf("server socket create succ!\n");
	
	//2. prepare IP and port
	//memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port	= htons(PORT);
	saddr.sin_addr.s_addr = INADDR_ANY;
	//inet_aton("192.168.0.100", &(saddr.sin_addr));
	bzero(&(saddr.sin_zero), 8);	

	//3. bind
	res = bind(serverfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
	if (-1 == res)
	{
		perror("server bind: ");
		return -1;
	}
	printf("bind succ!\n");

	//4. listen
	res = listen(serverfd, WAIT_QUEUE_LEN);
	if (-1 == res)
	{
		perror("server listen : ");
		return -1;
	}	
	printf("server listen...\n");
	
	//5. accept
	c_addrlen = sizeof(struct sockaddr_in);
	clientfd = accept(serverfd, (struct sockaddr *)&caddr, &c_addrlen);
	if (-1 == clientfd)
	{
		perror("server accept: ");
		return -1;
	}
	printf("server have a client, IP: %s \n", inet_ntoa(caddr.sin_addr));

	
	//6.send a welcome
	send(clientfd, WELCOME, strlen(WELCOME), 0);
	
	//7. interactive
	while ((len = recv(clientfd, buff, BUFF_SIZE, 0)) > 0)
	{
		buff[len] = '\0';
		printf("recv msg is : %s \n", buff);
		if (send(clientfd, buff, len, 0) < 0)
		{
			perror("server send: ");
			return -1;
		}
	}

	//8. close
	close(clientfd);
	close(serverfd);

	return 0;
}
