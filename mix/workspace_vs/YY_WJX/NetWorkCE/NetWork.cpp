// NetWork.cpp : 定义 DLL 应用程序的导出函数。

#include "NetWork.h"

UINT ThreadFunction(LPVOID pParam)//线程函数
{
	CNetwork * pNetWork = (CNetwork *)pParam;
	SOCKET sock =pNetWork->m_sock;
	UINT iRet;
	char buf[1024];
	int len = 1024;
	SOCKADDR_IN  fromAddr;
	int  fromAddrSize = sizeof(fromAddr);
	while(1)
	{
		memset(buf, 0, 1024);
		if ((iRet = recvfrom(sock, buf, len, 0,
			(SOCKADDR *)&fromAddr, &fromAddrSize)) == SOCKET_ERROR)
		{
			//ERROR
			return 0;
		}
		pNetWork->ReceiveUDP(buf, iRet,inet_ntoa(fromAddr.sin_addr),ntohs(fromAddr.sin_port));
		//printf("We successfully received %d bytes from address %s:%d.\n",iRet,
		//	inet_ntoa(fromAddr.sin_addr), ntohs(fromAddr.sin_port));
	}
	return 0;
}


CNetwork::CNetwork()
{
	m_pNetworkCallback = NULL;
	m_pRecvData = NULL;
	m_pThread = NULL;
	m_bflag = false;
	m_iError = 0;
	m_usSendPort = 0;
	m_usLocalPort = 0;
}

CNetwork::CNetwork(const Char *pLocalAddr, UInt16 usLocalPort)
{
	m_pNetworkCallback = NULL;
	m_pRecvData = NULL;
	m_pThread = NULL;
	m_bflag = false;
	m_iError = 0;
	m_usSendPort = 0;
	m_usLocalPort = 0;

	Open(pLocalAddr, usLocalPort);
}

//////////////////////////////////////////////////////////////////////
// ~CNetwork()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：
// CNetwork类析构函数
// 返回值：
// 无
// 创建人
// 2011-12-22 李强强
//////////////////////////////////////////////////////////////////////
CNetwork::~CNetwork()
{
	DWORD code;

	if(m_bflag)
	{
		if(GetExitCodeThread(m_pThread,&code))   //MonitorComm 你创建的线程句柄
		{
			if(code==STILL_ACTIVE)
			{
				TerminateThread(m_pThread,0);
				CloseHandle(m_pThread);
			}
		}
	}

	closesocket(m_sock);
	WSACleanup();

	delete [] m_pRecvData;
}

//////////////////////////////////////////////////////////////////////
// Open(const QString &strAddr, UInt16 usPort)
// 输入参数：
// strAddr	主机地址
// usPort	主机端口号
// 输出参数：
// 无
// 说明：
// 设置网络地址和端口号，并创建网络连接
// 返回值：
// 无
// 创建人
// 2011-12-22 李强强
//////////////////////////////////////////////////////////////////////
void CNetwork::Open(const Char *pLocalAddr, UInt16 usLocalPort)
{
	WSADATA              wsaData;
	int                  Ret;

	m_usLocalPort = usLocalPort;
	m_sockAddr.sin_family = AF_INET;
	m_sockAddr.sin_port = htons(usLocalPort);
	m_sockAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((Ret = WSAStartup(MAKEWORD(2,2), &wsaData)) != 0)
	{
		//ERROR
		return;
	}

	if ((m_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
	{
		//ERROR
		WSACleanup();
		return;
	}
	if (bind(m_sock, (SOCKADDR *)&m_sockAddr, sizeof(m_sockAddr))
		== SOCKET_ERROR)
	{
		//ERROR
		closesocket(m_sock);
		WSACleanup();
		return;
	}
}

//////////////////////////////////////////////////////////////////////
// SetCallback(IReceiveCallBack* pCallback)
// 输入参数：
// pCallback	指向IReceiveCallBack接口的指针
// 输出参数：
// 无
// 说明：
// 设置回调对象
// 返回值：
// 无
// 创建人
// 2011-12-22 李强强
//////////////////////////////////////////////////////////////////////
void CNetwork::SetCallback(IReceiveCallBack *pCallback)
{
	m_pNetworkCallback = pCallback;
}

//////////////////////////////////////////////////////////////////////
// SendUDP(const Byte* bSendingData, Int32 uiSendingSize, UInt32 uiAddr, UInt16 usPort)
// 输入参数：
// bSendingData		待发送数据
// uiSendingSize	待发送数据长度
// 输出参数：
// 无
// 说明：
// 发送UDP数据
// 返回值：
// 函数使用是否正确: 0：不成功。    >0：发送成功的个数
// 创建人
// 2011-12-22 李强强
//////////////////////////////////////////////////////////////////////
Int32 CNetwork::SendUDP(const Byte *pSendingData, Int32 iSendingSize)
{
	SOCKADDR_IN to;
	int iRet;
	to.sin_family = AF_INET;
	to.sin_port = htons(m_usSendPort);
	to.sin_addr.s_addr = inet_addr(m_strAddr);

	if ((iRet = sendto(m_sock, (const char *)pSendingData, iSendingSize, 0, 
		(SOCKADDR *)&to, sizeof(to))) == SOCKET_ERROR)
	{
		//ERROR
		return 0;
	}

	return iRet;
}

//////////////////////////////////////////////////////////////////////
// SocketError(QAbstractSocket::SocketError)
// 输入参数：
// uError		错误代码
// 输出参数：
// 无
// 说明：
// 设置发送错误代码
// 返回值：
// 无
// 创建人
// 2011-12-22 李强强
//////////////////////////////////////////////////////////////////////
void CNetwork::SocketError(Int32 uError)
{
	m_iError  = uError + 2;
}

//////////////////////////////////////////////////////////////////////
// ReadUDP()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：
// 读取UDP数据
// 返回值：
// 无
// 创建人
// 2011-12-22 李强强
//////////////////////////////////////////////////////////////////////
Bool CNetwork::ReadUDP()
{
	if(!m_bflag)
	{
		m_pThread = AfxBeginThread(ThreadFunction, this);
	}

	if(m_pThread != NULL)
	{
		m_bflag = true;
	}
	else
	{
		m_bflag = false;
	}

	return m_bflag;
}

//////////////////////////////////////////////////////////////////////
// ReceiveUDP()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：
// 接收UDP数据
// 返回值：
// 无
// 创建人
// 2011-12-22 李强强
//////////////////////////////////////////////////////////////////////
void CNetwork::ReceiveUDP(char *m_pRecvData, int iDataLen, char * strIP, UINT uiPort)
{
	if (m_pNetworkCallback != NULL)
	{
		if(iDataLen != 0)
		{
			m_pNetworkCallback->HandleReceiveData((const byte *)m_pRecvData, iDataLen);
		}
		else
		{
			m_pNetworkCallback->HandleError();
		}
	}

}

void CNetwork::SetSendPort(UInt16 usSendPort)
{
	m_usSendPort = usSendPort;
}

void CNetwork::SetSendAddr(const Char *pHostAddr)
{
	memset(m_strAddr, 0, 16);
	memcpy(m_strAddr,pHostAddr,strlen(pHostAddr));
}

Int32 CNetwork::SendData(const Byte *pData, Int32 iLen)
{
	if (SendUDP(pData, iLen) >= 0)
		return 0;
	else
		return -1;
}

Int32 CNetwork::ReceiveData(IReceiveCallBack *pCallBack)
{
	SetCallback(pCallBack);
	if (ReadUDP())
		return 0;
	else
		return -1;
}

void CNetwork::ResetCallBack()
{
	m_pNetworkCallback = NULL;
}