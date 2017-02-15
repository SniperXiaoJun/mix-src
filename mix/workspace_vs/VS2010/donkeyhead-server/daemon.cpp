#include <QtGui>
#include <QtNetwork>
#include <QRegExp>
#include <QString>
#include <QTableView>
#include <QPlastiqueStyle>
#include <QCleanlooksStyle>


#include "daemon.h"
#include "ui_daemon.h"
#include "tcpsockserver.h"
#include "sqlitedb.h"
#include "mysqlquerymodel.h"

Daemon::Daemon(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Daemon)
{
    ui->setupUi(this);
    this->setWindowTitle("QQ");
    ui->startListenButton->setText("开始监听");
    ui->ipLineEdit->setEnabled(true);
    ui->portLineEdit->setEnabled(true);

    ip.clear();
    port.clear();
    db = new SqliteDB;
    tableViewRefresh();

}

Daemon::~Daemon()
{
    delete ui;
}

void Daemon::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
    switch (e->type()) {
    case QEvent::LanguageChange:
        ui->retranslateUi(this);
        break;
    default:
        break;
    }
}

void Daemon::tableViewRefresh()
{
    db->connectDB();

    this->myModel = new MySqlQueryModel;
    this->myModel->setQuery(QObject::tr("select id, name, logstat from user order by logstat desc"));
    myModel->setHeaderData(0, Qt::Horizontal, tr("QQ号"));
    myModel->setHeaderData(1, Qt::Horizontal, tr("昵称"));
    myModel->setHeaderData(2, Qt::Horizontal, tr("状态"));

    ui->tableView->setModel(myModel);
    ui->tableView->setColumnWidth(0, 71);
    ui->tableView->setColumnWidth(1, 71);
    ui->tableView->setColumnWidth(2, 71);
    ui->tableView->show();


    db->closeDB();
}

void Daemon::on_startListenButton_clicked()
{
    ip.clear();
    port.clear();
    ip = ui->ipLineEdit->text().trimmed();
    port = ui->portLineEdit->text().trimmed();

    if ( "开始监听" == ui->startListenButton->text() )
    {
        //close listening
       // server.close();
        //QMessageBox::critical( NULL, tr("提示"), tr("2.") );
        //udpSocket->close();

        //use regular expression to verify input information
        QRegExp rxIp("\\d+\\.\\d+\\.\\d+\\.\\d+");
        QRegExp rxPort(("[1-9]\\d{3,4}"));
        rxIp.setPatternSyntax(QRegExp::RegExp);
        rxPort.setPatternSyntax(QRegExp::RegExp);

        if ( !rxPort.exactMatch(port) ||  !rxIp.exactMatch(ip) )
        {
            QMessageBox::critical( NULL, tr("提示"), tr("请输入正确的IP和端口.") );
        }
        else
        {
            //Tells the server to listen for incoming connections on address address and port port
            if ( !server.listen( QHostAddress(ip), (quint16)port.toUInt() ) )
            {
                QMessageBox::critical(NULL, tr("提示"), tr("TCP监听失败: %1.").arg(server.errorString() ) );
            }
            else
            {
                //When Tcp listen established, then start Udp bind.

                udpSocket = new QUdpSocket(this);
                if ( !udpSocket->bind(QHostAddress(ip), (quint16)port.toUInt()+1 ) )
                {
                    QMessageBox::critical(NULL, tr("提示"), tr("UDP绑定失败: %1.").arg(udpSocket->errorString() ) );
                }
                connect(udpSocket, SIGNAL(readyRead()), this, SLOT(on_read_Datagrams()));

                ui->startListenButton->setText("断开监听");
                ui->ipLineEdit->setEnabled(false);
                ui->portLineEdit->setEnabled(false);
            }

        }
    }

    else if ( "断开监听" == ui->startListenButton->text() )
    {
        //close listening
        server.close();
        udpSocket->close();
        ui->startListenButton->setText("开始监听");
        ui->ipLineEdit->setEnabled(true);
        ui->portLineEdit->setEnabled(true);
    }

}

void Daemon::on_read_Datagrams()
{
    //QMessageBox::critical(NULL, tr("提示"), tr("on_read_Datagrams.") );
    while (udpSocket->hasPendingDatagrams())
    {
        QByteArray block;
        block.resize(udpSocket->pendingDatagramSize());
        if ( -1 == udpSocket->readDatagram(block.data(), block.size(), &senderIp, &senderPort))
            continue;

        processDatagram(block);
    }

}

void Daemon::processDatagram(QByteArray block)
{
    QDataStream in(&block,QIODevice::ReadOnly);

    quint16 dataGramSize;
    QString msgType;  

    in >> dataGramSize >> msgType;
    /*变为手动刷新
    if ( "MSG_CLIENT_REGISTER_SUCCESS" == msgType )
    {
        tableViewRefresh();
    }
*/
    if ( "MSG_CLIENT_NEW_CONN" == msgType )
    {

        QString id;
        in >> id;
           QString data ;
           data = id;
       if ( !id.isEmpty() )
        {

            tableViewRefresh();
       }

        db->getUserAllOnline();
        QStringList idList = db->strListId;
        QStringList nameList = db->strListName;

        QString msgType = "MSG_ALL_USER_ONLINE";
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_4_6);
        out << (quint16)0 << msgType << idList << nameList;
        out.device()->seek(0);
        out << (quint16)(block.size() - sizeof(quint16));
        if ( !udpSocket->writeDatagram(block.data(), block.size(), senderIp, this->senderPort) )
        {
            QMessageBox::critical(NULL, tr("提示"), tr("!udpSocket->writeDatagram.") );
        }

        msgType= "MSG_NEW_USER_LOGIN";
        block.clear();
        out.device()->seek(0);
        db->getUserInfo(id);

        ui->listWidget->addItem("["+data+"]" + "is online");
        out << (quint16)0 << msgType << id << db->strListUser.at(2);
        out.device()->seek(0);
        out << (quint16)(block.size() - sizeof(quint16));
        if ( !udpSocket->writeDatagram(block.data(), block.size(), QHostAddress("255.255.255.255"), this->senderPort) )
        {
            QMessageBox::critical(NULL, tr("提示"), tr("!udpSocket->writeDatagram.") );
        }

    }


    if ( "MSG_USER_LOGOUT"==msgType )
    {
         QString id;
         QString data ;
        in >> id;
        data = id;

        if( id.isEmpty() )
        {
            ;
        }
        else
        {

            db->updateUserLogStat(id,"0");
            this->tableViewRefresh();

            msgType= "MSG_CLIENT_LOGOUT";

            block.clear();

            QDataStream out(&block,QIODevice::WriteOnly);
            out.device()->seek(0);
            db->getUserInfo(id);
            out << (quint16)0 << msgType << id << db->strListUser.at(2);
            out.device()->seek(0);


            ui->listWidget->addItem("["+data+"]" + "is offline");
            out << (quint16)(block.size() - sizeof(quint16));
            if ( !udpSocket->writeDatagram(block.data(), block.size(), QHostAddress("192.168.1.255"), 6666) )
            {
                QMessageBox::critical(NULL, tr("提示"), tr("!udpSocket->writeDatagram.") );
            }
        }
    }

    if( "MSG_CLIENT_CHAT" == msgType)
    {

        QString toid,fromId,fromName,toIp,buffer;
        in >> fromId >> toid >> buffer;

        db->getUserInfo(toid);
        toIp=db->strListUser.at(4);//to HostAddress

         db->getUserInfo(fromId);
        fromName=db->strListUser.at(2);

        QByteArray blockTosend;
        QDataStream tosend(&blockTosend,QIODevice::WriteOnly);
        QString mytype="MSG_CLIENT_CHAT";
        tosend<< (quint16)0 << mytype << fromName << fromId << buffer;

        tosend.device()->seek(0);

        tosend << (quint16)(blockTosend.size() - sizeof(quint16));

        if(!udpSocket->writeDatagram(blockTosend.data(), blockTosend.size(), QHostAddress(toIp),6666))
            QMessageBox::warning(NULL,"message sending","error");
    }

    if (msgType == "MSG_USER_MODI")
    {
        QString id;
        QString nickname2;
        QString pwd2;
        in >> id >> nickname2 >> pwd2;
        db->updateUser(id, nickname2, pwd2);
        this->tableViewRefresh();
    }
}

void Daemon::on_sendButton_clicked()
{
    QByteArray sysMsg;
    QDataStream tosend(&sysMsg,QIODevice::WriteOnly);
    tosend.setVersion(QDataStream::Qt_4_6);
    QString mytype="MSG_SERVER_INFO";
    tosend<<(quint16)0<<mytype<<ui->servTextEdit->toPlainText();
    tosend.device()->seek(0);
    tosend<<(quint16)(sysMsg.size()-sizeof(quint16));
    if(!udpSocket->writeDatagram(sysMsg.data(),sysMsg.size(),QHostAddress("192.168.1.255"),6666))
    QMessageBox::warning(NULL,"message broadcast","error");
    ui->servTextEdit->clear();
}

void Daemon::on_refreshButton_clicked()
{
    this->tableViewRefresh();
}

void Daemon::mousePressEvent(QMouseEvent *event)
{
    this->windowPos = this->pos();
        this->mousePos = event->globalPos();
        this->dPos = mousePos - windowPos;
}

void Daemon::mouseMoveEvent(QMouseEvent *event)
{
     this->move(event->globalPos() - this->dPos);
}

void Daemon::on_pushButton_clicked()
{
    this->db->closeDB();
    this->close();
}
