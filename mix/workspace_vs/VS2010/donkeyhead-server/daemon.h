/****************************************************************************
**
** Date    : 2010-07-07
** Author  : furtherchan
** E-Mail  : cnsilan@163.com

** If you have any questions , please contact me
**
****************************************************************************/


#ifndef DAEMON_H
#define DAEMON_H

#include <QMainWindow>
#include <QtNetwork>
#include <QtGui>
#include <QTableView>
#include <QTableWidget>
#include "sqlitedb.h"
#include "mysqlquerymodel.h"
#include "tcpsockserver.h"
#include <QPoint>

namespace Ui {
    class Daemon;
}

class Daemon : public QMainWindow {
    Q_OBJECT
public:
    Daemon(QWidget *parent = 0);
    ~Daemon();
    void tableViewRefresh();

protected:
    void changeEvent(QEvent *e);

    void mousePressEvent(QMouseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);

private:
    Ui::Daemon *ui;  
    SqliteDB *db;
    MySqlQueryModel *myModel;
    QPoint windowPos;
    QPoint mousePos;
    QPoint dPos;
    QUdpSocket *udpSocket;
    TcpSockServer server;
    QString ip;
    QString port;
    QHostAddress senderIp;
    quint16 senderPort;

    //member function
    void processDatagram(QByteArray block);



private slots:
    void on_pushButton_clicked();
    void on_refreshButton_clicked();
    void on_sendButton_clicked();
    void on_startListenButton_clicked();

    void on_read_Datagrams();
};

#endif // DAEMON_H

