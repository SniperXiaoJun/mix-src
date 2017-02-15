
#include <QtCore/QCoreApplication>
#include <QTcpServer>

#include "TcpServer.h"

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);

	
	CTcpServer * server = new CTcpServer;








	return a.exec();
}
