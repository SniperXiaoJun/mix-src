/****************************************************************************
**
** Date    : 2010-07-07
** Author  : furtherchan
** E-Mail  : cnsilan@163.com

** If you have any questions , please contact me
**
****************************************************************************/

#ifndef TCPSOCKSERVER_H
#define TCPSOCKSERVER_H

#include <QStringList>
#include <QTcpServer>

class TcpSockServer : public QTcpServer
{
    Q_OBJECT

public:
    TcpSockServer(QObject *parent = 0);

protected:
    void incomingConnection(int socketDescriptor);

private:

};

#endif // TCPSOCKSERVER_H

