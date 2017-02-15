#include "WinSocket.h"
#include "NetWork.h"


CWinSocket::CWinSocket(void)
{
	static bool bNetWorkON =false;
	m_pCallBack = NULL;

	if(!bNetWorkON)
	{
		bNetWorkON = true;
		if (!AfxSocketInit())
		{
			AfxMessageBox(_T("Failed to Initialize Sockets"), MB_OK | MB_ICONSTOP);
			return ;
		}
	}

	m_dwExpected = 0;
}

CWinSocket::~CWinSocket(void)
{

}

void CWinSocket::OnReceive(int nErrorCode)
{
	CAsyncSocket::OnReceive(nErrorCode);
	UINT uiPort;
	CString strIP;
	DWORD dwReceived;
	char buf[1024] = {0};

	if (IOCtl(FIONREAD, &dwReceived))
	{
		if (dwReceived >= m_dwExpected)   // Process only if you have enough data
		{
			ReceiveFrom(buf, sizeof(buf), strIP, uiPort);
			if(m_pCallBack != NULL)
			{
				m_pCallBack->ReceiveUDP(buf, dwReceived, strIP, uiPort);
			}
		}
	}
	else
	{
		// Error handling here
	}

}


bool CWinSocket::SetCallBack(CNetwork * pCallBack)
{
	if(pCallBack != NULL)
	{
		m_pCallBack = pCallBack;
		return true;
	}
	return false;
}