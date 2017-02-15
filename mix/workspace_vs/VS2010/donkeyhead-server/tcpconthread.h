/****************************************************************************
**
** Date    : 2010-07-07
** Author  : furtherchan
** E-Mail  : cnsilan@163.com

** If you have any questions , please contact me
**
****************************************************************************/



#ifndef TCPCONTHREAD_H
#define TCPCONTHREAD_H

#include <QThread>
#include <QTcpSocket>
#include "sqlitedb.h"
#include "daemon.h"


class TcpConThread : public QThread
{
    Q_OBJECT

public:

    //Constructer
    TcpConThread(int socketDescriptor, QObject *parent);
    void run();

signals:
    void error(QTcpSocket::SocketError socketError);

private:
    int socketDescriptor;
    QTcpSocket *tcpSocket;
    SqliteDB *db;


private slots:
    void on_Ready_Read();
};

#endif // TCPCONTHREAD_H
