// NetWork.cpp : ���� DLL Ӧ�ó���ĵ���������

#include "NetWork.h"
#include "WinSocket.h"

CNetwork::CNetwork()
{
	m_pNetworkCallback = NULL;
	m_pSocket = NULL;
	m_pRecvData = NULL;
	m_iError = 0;
	m_usSendPort = 0;
	m_usLocalPort = 0;
}

CNetwork::CNetwork(const Char *pLocalAddr, UInt16 usLocalPort)
{
	m_pNetworkCallback = NULL;
	m_pSocket = NULL;
	m_pRecvData = NULL;
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
	delete m_pSocket;
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
	m_usLocalPort = usLocalPort;
	if (m_pSocket == NULL)
	{
		m_pSocket = new CWinSocket;
		m_pSocket->Create(m_usLocalPort,SOCK_DGRAM);
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
	if (m_pSocket == NULL || m_usSendPort == 0 || m_strAddr.IsEmpty())
		return False;

	int iRet = m_pSocket->SendTo((const Char *)pSendingData,
		(Int64)iSendingSize, m_usSendPort, m_strAddr);
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
	m_bflag = m_pSocket->SetCallBack(this);
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
void CNetwork::ReceiveUDP(char *m_pRecvData, int iDataLen, CString strIP, UINT uiPort)
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
	m_strAddr = CString(pHostAddr);
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