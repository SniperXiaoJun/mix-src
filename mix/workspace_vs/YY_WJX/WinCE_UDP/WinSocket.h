#include <afxsock.h>

class CWinSocket: public CAsyncSocket
{
public:
	CWinSocket(void);
	~CWinSocket(void);

	void OnReceive(int nErrorCode);
};
