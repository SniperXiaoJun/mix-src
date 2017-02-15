#include <QtNetwork>
#include <QtGui>
#include <QMessageBox>

#include "tcpconthread.h"


TcpConThread::TcpConThread(int socketDescriptor, QObject *parent)
        : QThread(parent), socketDescriptor(socketDescriptor)
{

}


/****************************************************************************
**
** Creates a QTcpSocket, use Constructer passed in socketDescriptor to
** set the socket descriptor, and then stores the QTcpSocket in an internal
** list of pending connections.
** Finally newConnection() is emitted.
**
****************************************************************************/

void TcpConThread::run()
{

    tcpSocket = new QTcpSocket;

    connect(tcpSocket, SIGNAL(readyRead()), this, SLOT(on_Ready_Read()));

    if (!tcpSocket->setSocketDescriptor(socketDescriptor))
    {
        emit error(tcpSocket->error());
        return;
    }


    /****************************************************************************
    **
    ** Enters the event loop and waits until exit() is called, returning the
    ** value that was passed to exit(). The value returned is 0 if exit() is
    ** called via quit().
    ** It is necessary to call this function to start event handling.
    **
    ****************************************************************************/
    exec();

}

void TcpConThread::on_Ready_Read()
{
    /*QString strLogin = tcpSocket->readAll();
    QStringList strListUser = strLogin.split("|");
    QString id = strListUser.at(0);
    QString password = strListUser.at(1);*/

    db = new SqliteDB;

    QString ip = tcpSocket->peerAddress().toString();
    qint16 port = tcpSocket->peerPort();

    QByteArray block = tcpSocket->readAll();
    QDataStream in(&block, QIODevice::ReadOnly);     //QDataStream in(tcpSocket);
    quint16 dataGramSize;
    QString msgType;
    in >> dataGramSize >> msgType;

    if ( "MSG_CLIENT_USER_REGISTER" == msgType )
    {
        QString id;
        QString password;
        QString name;
        in >> id >> password >> name;

        if ( 0 == db->insertNewUser( id, password, name, ip, QString::number(port)) )
        {
            QMessageBox::warning(NULL, tr("提示"), tr("该号码已被注册."));
            QString msgType = "MSG_ID_ALREADY_EXIST";
            QByteArray block;
            QDataStream out(&block, QIODevice::WriteOnly);
            out.setVersion(QDataStream::Qt_4_6);
            out << (quint16)0 << msgType;
            out.device()->seek(0);
            out << (quint16)(block.size() - sizeof(quint16));
            tcpSocket->write(block);
        }
        else
        {
            QByteArray block;

            QDataStream out(&block, QIODevice::WriteOnly);
            out.setVersion(QDataStream::Qt_4_6);
            QString msgType = "MSG_REGISTER_SUCCESS";
            out << (quint16)0 << msgType;
            out.device()->seek(0);
            out << (quint16)(block.size() - sizeof(quint16));
            tcpSocket->write(block);
        }
    }
    else if ( "MSG_USER_LOGIN" == msgType )
    {
        QString id;
        QString password;
        in >> id >> password;
        db->getUserInfo(id);

        if (db->strListUser.isEmpty())        //MSG_ID_NOTEXIST
        {
             QMessageBox::critical(NULL, tr("提示"), tr("没有名字") );
            QByteArray block;
            QDataStream out(&block, QIODevice::WriteOnly);
            out.setVersion(QDataStream::Qt_4_6);
            QString msgType = "MSG_ID_NOTEXIST";
            out << (quint16)0 << msgType;
            out.device()->seek(0);
            out << (quint16)(block.size() - sizeof(quint16));
            tcpSocket->write(block);

        }
        else if(db->strListUser.at(1) != password)        //MSG_PWD_ERROR
        {

            QByteArray block;
            QDataStream out(&block, QIODevice::WriteOnly);
            out.setVersion(QDataStream::Qt_4_6);
            QString msgType = "MSG_PWD_ERROR";
            out << (quint16)0 << msgType;
            out.device()->seek(0);
            out << (quint16)(block.size() - sizeof(quint16));
            tcpSocket->write(block);
        }
        else if (db->strListUser.at(1) == password )
        {
            if ((db->strListUser.at(3)) == "1")          //MSG_LOGIN_ALREADY
            {

                QByteArray block;
                QDataStream out(&block, QIODevice::WriteOnly);
                out.setVersion(QDataStream::Qt_4_6);
                QString msgType = "MSG_LOGIN_ALREADY";
                out << (quint16)0 << msgType;
                out.device()->seek(0);
                out << (quint16)(block.size() - sizeof(quint16));
                tcpSocket->write(block);


            }
            else            //MSG_LOGIN_SUCCESS
            {
                QByteArray block;
                QDataStream out(&block, QIODevice::WriteOnly);
                out.setVersion(QDataStream::Qt_4_6);
                QString msgType = "MSG_LOGIN_SUCCESS";
                out << (quint16)0 << msgType;
                out.device()->seek(0);
                out << (quint16)(block.size() - sizeof(quint16));
                tcpSocket->write(block);
                //login success, update database
                db->updateUserLogStat(id, "1");
                db->updateUserIp(id,tcpSocket->peerAddress().toString());
            }

        }
    }

}


