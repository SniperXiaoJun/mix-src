#ifndef CCOPYTHREAD_H
#define CCOPYTHREAD_H

#include <QThread>

class CCopyThread : public QThread
{
	Q_OBJECT

public:
	CCopyThread(QObject *parent = 0);
	~CCopyThread();

	void run();

	void TraverseFun(QString filename);

	int SetFileNameNew(QString fileName);
	QString GetFileNameNew();
	int SetFileNameOld(QString fileName);
	QString GetFileNameOld();

signals:
	void SignalPassByte(qint64,const QString&, const QString&);

private:
	QString m_strFileNameOld;
	QString m_strFileNameNew;
};

#endif // CCOPYTHREAD_H
