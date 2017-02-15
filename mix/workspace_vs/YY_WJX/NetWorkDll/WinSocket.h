#include <afxsock.h>

class CNetwork;

class CWinSocket: public CAsyncSocket
{
public:
	CWinSocket(void);
	~CWinSocket(void);

	void OnReceive(int nErrorCode);
	bool SetCallBack(CNetwork * pCallBack = NULL);

private :
	DWORD m_dwExpected;
	CNetwork * m_pCallBack;
};
