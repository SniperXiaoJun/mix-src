
#include <QtCore/QCoreApplication>
#include "WinSocket.h"

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);

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

	i = sock.SendTo("111", 3, 8888, "127.0.0.1");

	i = sock.GetLastError();



	//WSANOTINITIALISED

	

	return a.exec();
}
