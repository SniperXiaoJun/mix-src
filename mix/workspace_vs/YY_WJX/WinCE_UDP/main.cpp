#include "wince_udp.h"

#include "WinSocket.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);


	if (!AfxSocketInit())
	{
		AfxMessageBox(_T("Failed to Initialize Sockets"), MB_OK | MB_ICONSTOP);
		return FALSE;
	}

	CWinSocket sock;

	bool bBroadCast  = true;

	int i = sock.Create(8888, SOCK_DGRAM);

	//i = sock.Bind(5555, "127.0.0.1");

	//i = sock.SetSockOpt(SO_REUSEADDR, &bBroadCast, sizeof(bool), SOL_SOCKET);

	LPCTSTR pIp = NULL;

	pIp = malloc(sizeof(100));

	memcpy((void *)pIp,"127.0.0.1", sizeof("127.0.0.1"));
	i = sock.SendTo("111", 3, 8888, pIp);

	i = sock.GetLastError();


	WinCE_UDP w;
	w.showMaximized();
	return a.exec();
}
