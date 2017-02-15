#include "YY_CHAT_ThreadClient.h"

YY_CHAT_ThreadClient::YY_CHAT_ThreadClient(QObject *parent)
{
	m_pTcpSocket = new QTcpSocket(this);
	m_pTcpSocket->connectToHost(QHostAddress::QHostAddress("128.1.1.142"), 8888);
    connect(m_pTcpSocket, SIGNAL(readyRead()), this, SLOT(SlotRead()));
}

YY_CHAT_ThreadClient::~YY_CHAT_ThreadClient()
{
	delete m_pTcpSocket;
}

int YY_CHAT_ThreadClient::SetFileName(QString fileName)
{
	m_FileName = fileName;
	return 0;
}

QString YY_CHAT_ThreadClient::GetFileName()
{
	return m_FileName;
}

int YY_CHAT_ThreadClient::SetFileLength(quint64 length)
{
	m_FileLength = length;
	return 0;
}

quint64 YY_CHAT_ThreadClient::GetFileLength()
{
	return m_FileLength;
}

void YY_CHAT_ThreadClient::SlotRead()
{

    start();
//	QFile file(m_FileName);

//	if (!file.open(QIODevice::WriteOnly | QIODevice::Append))
//	{
//		return;
//	}

//	while (!m_pTcpSocket->atEnd()) {
//		QByteArray data = m_pTcpSocket->read(100);
//		file.write(data);
//	}

//	file.close();
}

void YY_CHAT_ThreadClient::run()
{
    QFile file(m_FileName);

    if (!file.open(QIODevice::WriteOnly | QIODevice::Append))
    {
        return;
    }

    while (!m_pTcpSocket->atEnd()) {
        QByteArray data = m_pTcpSocket->read(100);
        file.write(data);
    }

    file.close();
}
