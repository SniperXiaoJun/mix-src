#include "YY_CHAT_ThreadServer.h"

YY_CHAT_ThreadServer::YY_CHAT_ThreadServer(QObject *parent)
{
	m_pTcpServer = new QTcpServer;
	m_pTcpSocket = NULL;
	m_pTcpServer->listen(QHostAddress::Any, 8888);
	connect(m_pTcpServer, SIGNAL(newConnection()), this, SLOT(SlotConnect()));
}

YY_CHAT_ThreadServer::~YY_CHAT_ThreadServer()
{

}

void YY_CHAT_ThreadServer::SlotConnect()
{
	if(m_pTcpServer->hasPendingConnections())
	{
		m_pTcpSocket = m_pTcpServer->nextPendingConnection();
		m_ListTcpSocket.append(m_pTcpSocket);
		run();
	}
}

void YY_CHAT_ThreadServer::run()
{
	QFile file(m_FileName);
	quint64 fileLength = QFileInfo(m_FileName).size();
	quint64 filePos = 0;
	int maxByte = 1024 * 1024;
	int readByteNum = 0;
	QByteArray byteArray;

	if (!file.open(QIODevice::ReadOnly))
	{
		return;
	}

	for(filePos; filePos < fileLength; filePos += readByteNum)
	{
		byteArray = file.read(maxByte);
		readByteNum = byteArray.count();
		m_pTcpSocket->write(byteArray);
		//m_pTcpSocket->bytesToWrite();
		emit SignalPassByte(filePos);
	}
}

int YY_CHAT_ThreadServer::SetFileName(QString fileName)
{
	m_FileName = fileName;
	return 0;
}

QString YY_CHAT_ThreadServer::GetFileName()
{
	return m_FileName;
}