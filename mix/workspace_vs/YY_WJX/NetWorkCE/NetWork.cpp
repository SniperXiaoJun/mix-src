// NetWork.cpp : ���� DLL Ӧ�ó���ĵ���������

#include "NetWork.h"

UINT ThreadFunction(LPVOID pParam)//�̺߳���
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
// ���������
// ��
// ���������
// ��
// ˵����
// CNetwork����������
// ����ֵ��
// ��
// ������
// 2011-12-22 ��ǿǿ
//////////////////////////////////////////////////////////////////////
CNetwork::~CNetwork()
{
	DWORD code;

	if(m_bflag)
	{
		if(GetExitCodeThread(m_pThread,&code))   //MonitorComm �㴴�����߳̾��
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
// ���������
// strAddr	������ַ
// usPort	�����˿ں�
// ���������
// ��
// ˵����
// ���������ַ�Ͷ˿ںţ���������������
// ����ֵ��
// ��
// ������
// 2011-12-22 ��ǿǿ
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
// ���������
// pCallback	ָ��IReceiveCallBack�ӿڵ�ָ��
// ���������
// ��
// ˵����
// ���ûص�����
// ����ֵ��
// ��
// ������
// 2011-12-22 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CNetwork::SetCallback(IReceiveCallBack *pCallback)
{
	m_pNetworkCallback = pCallback;
}

//////////////////////////////////////////////////////////////////////
// SendUDP(const Byte* bSendingData, Int32 uiSendingSize, UInt32 uiAddr, UInt16 usPort)
// ���������
// bSendingData		����������
// uiSendingSize	���������ݳ���
// ���������
// ��
// ˵����
// ����UDP����
// ����ֵ��
// ����ʹ���Ƿ���ȷ: 0�����ɹ���    >0�����ͳɹ��ĸ���
// ������
// 2011-12-22 ��ǿǿ
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
// ���������
// uError		�������
// ���������
// ��
// ˵����
// ���÷��ʹ������
// ����ֵ��
// ��
// ������
// 2011-12-22 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CNetwork::SocketError(Int32 uError)
{
	m_iError  = uError + 2;
}

//////////////////////////////////////////////////////////////////////
// ReadUDP()
// ���������
// ��
// ���������
// ��
// ˵����
// ��ȡUDP����
// ����ֵ��
// ��
// ������
// 2011-12-22 ��ǿǿ
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
// ���������
// ��
// ���������
// ��
// ˵����
// ����UDP����
// ����ֵ��
// ��
// ������
// 2011-12-22 ��ǿǿ
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