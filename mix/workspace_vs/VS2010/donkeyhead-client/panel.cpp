#include "panel.h"
#include "ui_panel.h"

panel::panel(QString usrname, QString ip, QString port, QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::panel)
{
    ui->setupUi(this);
    this->ip = ip;
    this->port = port;
    this->usrname = usrname;
    this->flag = false;
    this->resize(201, 492);
    this->init();
}

panel::~panel()
{
    delete ui;
}

void panel::init()
{
    udpSocket = new QUdpSocket(this);
    udpSocket->bind(6666);
    QString msgType = "MSG_CLIENT_NEW_CONN";
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_4_6);
    out << (quint16)0 << msgType << usrname;
    out.device()->seek(0);
    udpSocket->writeDatagram(block.data(), block.size(), QHostAddress(ip), (quint16)port.toUInt()+1);
    connect(this->udpSocket, SIGNAL(readyRead()), this, SLOT(recvMsg()));
}

void panel::changeEvent(QEvent *e)
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

void panel::recvMsg()
{
    QByteArray block;
    QString msgType;
    QStringList idList;
    QStringList nicknameList;
    quint16 size;
    QHostAddress peerIp;
    quint16 peerPort;
    block.resize(udpSocket->pendingDatagramSize());
    this->udpSocket->readDatagram(block.data(),block.size(),&peerIp,&peerPort);
    QDataStream in(&block,QIODevice::ReadOnly);
    in.setVersion(QDataStream::Qt_4_6);
    in>>size>>msgType;

    if ("MSG_ALL_USER_ONLINE" == msgType)
    {
        in >> idList >> nicknameList;
        for (int i=0; i<idList.count(); i++)
        {
            QString itemString;
            itemString = nicknameList.at(i) + "[" + idList.at(i) +"]";
            ui->usrlistWidget->addItem(itemString);
        }
        ui->countlabel->setText(QString::number(ui->usrlistWidget->count()) + "个用户在线");
    }
    if ("MSG_CLIENT_CHAT" == msgType)
    {
        QString peerName;
        QString peerId;
        QString msg;
        in>>peerName>>peerId>>msg;

       QString valueHash;
       valueHash.append(peerName + "[" + peerId + "]");
       chatform *c;
       if(chatformHash.contains(valueHash))
       {
             c = chatformHash.value(valueHash);
        }
       else
       {
             c = new chatform(this->usrname,this->ip,this->port,this->udpSocket);
             c->setWindowTitle("chatting with " + peerName + "(" + peerId + ").");
             chatformHash.insert(valueHash,c);

        }



       c->show();

       c->displayText(peerName,peerId,msg);
    }
    if ("MSG_SERVER_INFO" == msgType)
    {
        QString msg;
        in >> msg;
        ui->serverlistWidget->addItem("<server>"+msg);
    }
    if ("MSG_NEW_USER_LOGIN" == msgType)
    {
        QString peerName;
        QString peerId;
        QString user;
        in >> peerId >> peerName;
        if (this->usrname != peerId)
        {
            user.append(peerName + "["+peerId+"]");
            for (int i=0; i < ui->usrlistWidget->count(); i++)
            {
                if (ui->usrlistWidget->item(i)->text() == user)
                {
                    delete ui->usrlistWidget->takeItem(i);
                }
            }
            ui->usrlistWidget->addItem(user);
            ui->serverlistWidget->addItem(user+" login.");
            ui->countlabel->setText(QString::number(ui->usrlistWidget->count()) + "头驴在聊……");
        }
    }
    if ("MSG_CLIENT_LOGOUT" == msgType)
    {

    }

}

void panel::on_quitButton_clicked()
{
    //QMessageBox::StandardButton rb = QMessageBox::question(this, "message", "Do you want to quit?",     QMessageBox::No | QMessageBox::Yes,    QMessageBox::Yes);

    //if(rb ==  QMessageBox::Yes)
   // {
        QString msgType = "MSG_USER_LOGOUT";
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_4_6);
        out << (quint16)0 << msgType << usrname;
        out.device()->seek(0);
        out << (quint16)(block.size() - sizeof(quint16));
        if (!udpSocket->writeDatagram(block.data(), block.size(), QHostAddress(ip), (quint16)port.toUInt()+1))
        {
            QMessageBox::warning(NULL, tr("udpSocket"), tr("writeDatagram."));
        }
        this->close();
        // }
}

void panel::closeEvent(QCloseEvent *e)
{
    panel::on_quitButton_clicked();
}

void panel::on_setButton_clicked()
{
    if (flag == false)
    {
        this->resize(201, 615);
        flag = true;
    }
    else
    {
        this->resize(201, 492);
        flag = false;
    }
}

void panel::on_usrlistWidget_itemDoubleClicked(QListWidgetItem* item)
{
    QString nameStr = ui->usrlistWidget->currentItem()->text();

    nameStr.replace("\n","");
    //QString tempstr(nameStr);
    chatform *c = chatformHash.value(nameStr);
    if(c == 0)
    {
    //    QMessageBox::warning(NULL, tr("udpSocket"), tr("hash."));
        c = new chatform(this->usrname,this->ip,this->port, udpSocket);
        c->setWindowTitle("chatting with " + nameStr + ".");
        chatformHash.insert(nameStr,c);//??

    }
    c->setWindowFlags(Qt::FramelessWindowHint);
    c->setAttribute(Qt::WA_TranslucentBackground);

    c->show();
}

void panel::on_editButton_clicked()
{
    QString msgType = "MSG_USER_MODI";
    QString nickname2 = ui->editnicknamelineEdit->text().trimmed();
    QString pwd2 = ui->editpwdlineEdit->text().trimmed();
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_4_6);
    out << (quint16)0 << msgType << usrname << nickname2 << pwd2;
    out.device()->seek(0);
    out << (quint16)(block.size() - sizeof(quint16));
    if (!udpSocket->writeDatagram(block.data(), block.size(), QHostAddress(ip), (quint16)port.toUInt()+1))
{
    QMessageBox::warning(NULL, tr("udpSocket"), tr("writeDatagram."));
}
 ui->editnicknamelineEdit->clear();
 ui->editpwdlineEdit->clear();
  QMessageBox::information(this, "提示", "设置成功");
  this->resize(201, 492);
  flag = false;

}


void panel::mousePressEvent(QMouseEvent *event)
{
    this->windowPos = this->pos();
            this->mousePos = event->globalPos();
            this->dPos = mousePos - windowPos;
}

void panel::mouseMoveEvent(QMouseEvent *event)
{
   this->move(event->globalPos() - this->dPos);
}

void panel::on_pushButton_clicked()
{
    this->close();

}
