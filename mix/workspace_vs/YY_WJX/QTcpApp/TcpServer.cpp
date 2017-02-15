#include "TcpServer.h"
#include <QByteArray>

CTcpServer::CTcpServer(void)
{
	server = new QTcpServer(NULL);
	server->listen(QHostAddress::Null, 8888);
	QObject::connect(server, SIGNAL(newConnection()), this, SLOT(getConnect()));


	socketdd = new QTcpSocket;

	socketdd->connectToHost( "128.1.1.142", 8888);
	QObject::connect(socketdd, SIGNAL(readyRead()), this, SLOT(Read()));
}

CTcpServer::~CTcpServer(void)
{
}

void CTcpServer::getConnect()
{
	if(server->hasPendingConnections())
	{
		socket = server->nextPendingConnection();
	}
	socket->write("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

void CTcpServer::Read()
{
	while (!socketdd->atEnd()) {
		QByteArray data = socketdd->read(100);
	}
}