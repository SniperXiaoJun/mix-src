#include<WinSock2.h>
#include<WS2tcpip.h>
#include<stdio.h>

#pragma comment(lib,"ws2_32.lib")		//windows socket 2
#pragma comment(lib,"mswsock.lib")		//microsoft windows 2 socket
#pragma comment(lib,"advapi32.lib")		//advanced api 32

#define DEFAULT_BUFLEN		512
#define DEFAULT_PORT		"13233"

int main(int argc, char** agrv)
{
	int iRet;
	WSADATA wsadata;
	struct addrinfo hints;
	struct addrinfo* pstResult;
	SOCKET Server_Socket = INVALID_SOCKET;
	struct sockaddr ClientAddr;
	int ClientAddrLen = sizeof(ClientAddr);
	int iRecv, iSend;
	char str[100];
	char RecvBuf[DEFAULT_BUFLEN];
	int RecvBufLen = DEFAULT_BUFLEN;
	char *pRecv;

	/*对windows socket进行初始化*/
	iRet = WSAStartup(MAKEWORD(2,2),&wsadata);
	if (0 != iRet)
	{
		printf("server WSAStartup failed with error: %d line: %d\n", iRet, __LINE__);
		return 1;
	}

	ZeroMemory(&hints,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	iRet = getaddrinfo(NULL,DEFAULT_PORT,&hints,&pstResult);
	if (0 != iRet)
	{
		printf("server getaddrinfo failed with error: %d line: %d\n", iRet, __LINE__);
		WSACleanup();
		return 1;
	}

	Server_Socket = socket(pstResult->ai_family, pstResult->ai_socktype,pstResult->ai_protocol);
	if (INVALID_SOCKET == Server_Socket)
	{
		printf("server socket failed with error: %d line: %d\n", WSAGetLastError(), __LINE__);
		freeaddrinfo(pstResult);
		WSACleanup();
		return 1;
	}

	iRet = bind(Server_Socket, pstResult->ai_addr, (int)pstResult->ai_addrlen);
	if (SOCKET_ERROR == iRet)
	{
		printf("server bind failed with error: %d line: %d\n", WSAGetLastError(), __LINE__);
		closesocket(Server_Socket);
		freeaddrinfo(pstResult);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(pstResult);

	do
	{
		iRecv = recvfrom(Server_Socket, RecvBuf, RecvBufLen, 0, &ClientAddr, &ClientAddrLen);
		if (iRecv > 0)
		{
			printf("server recvfrom Byte: %d\n", iRecv);
			pRecv = RecvBuf;
			while(iRecv > 0)
			{
				iSend = sendto(Server_Socket, pRecv, iRecv, 0, &ClientAddr, ClientAddrLen);
				if (SOCKET_ERROR == iSend)
				{
					itoa(WSAGetLastError(),str,10);
					printf("server sendto failed with error: %s line: %d\n", str, __LINE__);
					closesocket(Server_Socket);
					WSACleanup();
					return 1;
				}
				iRecv -= iSend;
				pRecv += iSend;
			}
		}
		else if (0 == iRecv)
		{
			printf("server closing connect!\n");
		}
		else
		{
			printf("server recvfrom failed with error: %d line: %d\n", iRecv, __LINE__);
			closesocket(Server_Socket);
			WSACleanup();
			return 1;
		}
	}while (1);

	closesocket(Server_Socket);
	WSACleanup();
	return 0;
}
