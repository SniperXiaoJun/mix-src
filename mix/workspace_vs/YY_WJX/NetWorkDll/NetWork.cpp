// NetWork.cpp : 定义 DLL 应用程序的导出函数。

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
	delete m_pSocket;
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
	m_usLocalPort = usLocalPort;
	if (m_pSocket == NULL)
	{
		m_pSocket = new CWinSocket;
		m_pSocket->Create(m_usLocalPort,SOCK_DGRAM);
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
	if (m_pSocket == NULL || m_usSendPort == 0 || m_strAddr.IsEmpty())
		return False;

	int iRet = m_pSocket->SendTo((const Char *)pSendingData,
		(Int64)iSendingSize, m_usSendPort, m_strAddr);
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
	m_bflag = m_pSocket->SetCallBack(this);
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