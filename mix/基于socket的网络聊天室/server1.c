//TCP聊天室服务器
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int sockfd;//服务器socket
int fds[100];//客户端的socket
int size = 0;//客户端的数量

char* IP ="127.0.0.1";
short PORT = 12222;
typedef struct sockaddr SA;
void init(){//初始化服务器
	printf("聊天室服务器开始启动\n");
	sockfd = socket(PF_INET,SOCK_STREAM,0);
	if(sockfd == -1){
		perror("创建socket失败");
		printf("服务器启动失败\n");
		exit(-1);
	}
	struct sockaddr_in addr;
	addr.sin_family = PF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = inet_addr(IP);
	if(bind(sockfd,(SA*)&addr,sizeof(addr)) == -1){
		perror("绑定失败");
		printf("服务器启动失败\n");
		exit(-1);
	}
	printf("地址成功绑定\n");
	if(listen(sockfd,100) == -1){
		perror("设置监听失败");
		printf("服务器启动失败\n");
		exit(-1);
	}
	printf("设置监听成功\n");
	printf("初始化服务器成功\n");
}

void sendMsgToAll(char* msg){//给每个客户端发送信息
	int i;
	for(i=0;i<size;i++){
		if(fds[i]!=0){
			printf("send to %d\n",fds[i]);
			send(fds[i],msg,strlen(msg),0);
		}
	}
}

void* service_thread(void* p){//每个线程的执行函数
	int fd = *(int*)p;
	printf("pthread = %d\n",fd);
	while(1){
		char buf[100] = {};
		if(recv(fd,buf,sizeof(buf),0) <= 0){
			printf("fd = %d quit\n",fd);
			int i;
			for(i=0;i<size;i++){
				if(fd == fds[i]){
					fds[i] = 0;
					i = 0;
				}
			}
			printf("quit->fd = %d quit\n",fd);
			return ;
		}
		//发给所有的客户端
		sendMsgToAll(buf);
	}
}

void service(){//服务器工作的函数
	printf("服务器开始服务\n");
	while(1){
		struct sockaddr_in fromaddr;
		socklen_t len = sizeof(fromaddr);
		int fd = accept(sockfd,(SA*)&fromaddr,&len);
		if(fd == -1){
			printf("客户端连接出错...\n");
			continue;
		}
		//记录客户端的socket
		fds[size++] = fd;
		printf("fd = %d\n",fd);
		//有客户端连接之后，启动线程给此客户服务
		pthread_t tid;
		pthread_create(&tid,0,service_thread,&fd);
	}
}

int main(){
	init();
	service();
	int i;
	for(i=0;i<size;i++){
		pthread_join(fds[i],(void**)0);
		printf("quitid == %d\n",fds[i]);
		fds[i] = 0;
	}
}

