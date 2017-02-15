#include "stdafx.h"

#include "WinSocket.h"


CWinSocket::CWinSocket(void)
{	
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
			char * p = buf;
			char * q = buf;
		}
	}
	else
	{
		// Error handling here
	}

}
