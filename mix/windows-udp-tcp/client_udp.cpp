#include<WinSock2.h>
#include<WS2tcpip.h>
#include<stdio.h>
#include<string.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"mswsock.lib")
#pragma comment(lib,"advapi32.lib")

#define DEFAULT_PORT "13233"
#define DEFAULT_IP   "127.0.0.1"
#define DEFAULT_BUFLEN 256

int main(int argc, char** argv)
{
	int iRet;
	WSADATA wsadata;
	struct addrinfo * pstResult = NULL ;
	struct addrinfo hints;
	SOCKET Client_Socket = INVALID_SOCKET;
	int iSend, iRecv;
	char SendBuf[DEFAULT_BUFLEN];
	char *pSend;
	int SendBufLen = DEFAULT_BUFLEN;

	iRet = WSAStartup(MAKEWORD(2,2),&wsadata);
	if (0 != iRet)
	{
		printf("client WSAStartup failed with error: %d line: %d\n", iRet, __LINE__);
		return 1;
	}

	ZeroMemory(&hints,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	iRet = getaddrinfo("localhost", DEFAULT_PORT, &hints, &pstResult);
	if (0 != iRet)
	{
		printf("client getaddrinfo failed with error: %d line:%d\n", iRet, __LINE__);
		WSACleanup();
		return 1;
	}

	//Client_Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	Client_Socket = socket(pstResult->ai_family, pstResult->ai_socktype, pstResult->ai_protocol);
	if (INVALID_SOCKET == Client_Socket)
	{
		printf("client socket failed with error: %d line: %d\n", WSAGetLastError(), __LINE__);
		freeaddrinfo(pstResult);
		WSACleanup();  
		return 1;
	}

	//freeaddrinfo(pstResult);

	while('\0' != *gets_s(SendBuf,sizeof(SendBuf)))
	{
		SendBufLen = strlen(SendBuf);
		pstResult->ai_addrlen = sizeof(struct sockaddr);
		pSend = SendBuf;
		while(SendBufLen > 0)
		{
			iSend = sendto(Client_Socket, pSend, SendBufLen, 0, pstResult->ai_addr,pstResult->ai_addrlen); 
			if (SOCKET_ERROR == iSend)
			{
				printf("client sendto failed with error: %d line: %d\n", WSAGetLastError(), __LINE__);
				closesocket(Client_Socket);
				WSACleanup();
				return 1;
			}
			else 
			{
				printf("client sendto Byte: %d\n", iSend);
				SendBufLen -= iSend;
				pSend += iSend;
			}
		}

		//iSend = 0;
		pSend = SendBuf;
		SendBufLen = DEFAULT_BUFLEN;
		do
		{
			iRecv = recvfrom(Client_Socket, pSend, SendBufLen, 0, pstResult->ai_addr,(int *) &(pstResult->ai_addrlen));
			if (iRecv > 0)
			{
				printf("client recvfrom Byte: %d\n", iRecv);
				pSend += iRecv;
				SendBufLen -= iRecv;
				//iSend += iRecv;
			}
			else if (0 == iRecv)
			{
				printf("client closing connect!\n");
				iSend = pSend - SendBuf; 

			}
			else
			{
				printf("client recvfrom failed with error: %d line: %d\n", WSAGetLastError(), __LINE__);
				closesocket(Client_Socket);
				WSACleanup();
				return 1;
			}
		}while(iRecv > 0);
	}

	closesocket(Client_Socket);
	WSACleanup();
	return 0;
}
