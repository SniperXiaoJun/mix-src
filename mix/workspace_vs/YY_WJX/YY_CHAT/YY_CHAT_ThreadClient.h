#ifndef YY_CHAT_THREADCLIENT_H
#define YY_CHAT_THREADCLIENT_H

#include <QThread>
#include <QTcpSocket>
#include <QHostAddress>
#include <QFile>

class YY_CHAT_ThreadClient:QObject
{
	Q_OBJECT

public:
	YY_CHAT_ThreadClient(QObject *parent);
	~YY_CHAT_ThreadClient();

	int SetFileName(QString fileName);
	QString GetFileName();

	int SetFileLength(quint64 length);
	quint64 GetFileLength();

public slots:
	void SlotRead();

private:
	QTcpSocket * m_pTcpSocket;
	quint64 m_FileLength;
	QString m_FileName;
};

#endif // YY_CHAT_THREADCLIENT_H
