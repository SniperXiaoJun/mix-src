#ifndef YY_CHAT_THREADSERVER_H
#define YY_CHAT_THREADSERVER_H

#include <QThread>
#include <QTcpServer>
#include <QFile>
#include <QFileInfo>
#include <QTcpSocket>

class YY_CHAT_ThreadServer : public QThread
{
	Q_OBJECT

public:
	YY_CHAT_ThreadServer(QObject *parent);
	~YY_CHAT_ThreadServer();

	void run();

	int SetFileName(QString fileName);
	QString GetFileName();

public slots:
	void SlotConnect();

signals:
	void SignalPassByte(qint64);

private:
	QTcpServer * m_pTcpServer;
	QTcpSocket * m_pTcpSocket;
	QList<QTcpSocket *> m_ListTcpSocket;
	QString m_FileName;
};

#endif // YY_CHAT_THREADSERVER_H
