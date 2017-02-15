/****************************************************************************
**
** Date    : 2010-07-07
** Author  : furtherchan
** E-Mail  : cnsilan@163.com

** If you have any questions , please contact me
**
****************************************************************************/

#include "tcpsockserver.h"
#include "tcpconthread.h"

TcpSockServer::TcpSockServer(QObject *parent)
     : QTcpServer(parent)
{
}


/****************************************************************************
**
** Reimplement this function to alter the server's behavior when a connection
** is available.
**
****************************************************************************/

void TcpSockServer::incomingConnection(int socketDescriptor)
{
    TcpConThread *thread = new TcpConThread(socketDescriptor, this);
    connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));
    thread->start();
}
