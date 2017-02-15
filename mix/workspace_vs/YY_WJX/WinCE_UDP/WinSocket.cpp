#include "WinSocket.h"

CWinSocket::CWinSocket(void)
{

}

CWinSocket::~CWinSocket(void)
{

}

void CWinSocket::OnReceive(int nErrorCode)
{
	CAsyncSocket::OnReceive(nErrorCode);

	DWORD dwReceived;

	if (IOCtl(FIONREAD, &dwReceived))
	{

	}
	else
	{
		// Error handling here
	}

}
