#include "regdialog.h"
#include "ui_regdialog.h"

regdialog::regdialog(QString ip, QString port, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::regdialog)
{
    ui->setupUi(this);
    this->ip = ip;
    this->port = port;
    this->setWindowTitle("用户注册");

    tcpSocket = new QTcpSocket(this);

    connect(tcpSocket, SIGNAL(readyRead()), this, SLOT(on_ready_Read()));

}

regdialog::~regdialog()
{
    delete ui;
}

void regdialog::changeEvent(QEvent *e)
{
    QDialog::changeEvent(e);
    switch (e->type()) {
    case QEvent::LanguageChange:
        ui->retranslateUi(this);
        break;
    default:
        break;
    }
}

void regdialog::on_submitButton_clicked()
{
    QString usrname = ui->usrnamelineEdit->text().trimmed();
    QString password = ui->passwordlineEdit->text().trimmed();
    QString password2 = ui->password2lineEdit->text().trimmed();
    QString nickname = ui->nicknamelineEdit->text().trimmed();

    QRegExp rx("^[1-9]{1,2}[0-9]{4,7}$");
    rx.setPatternSyntax(QRegExp::RegExp);
    
    if (!rx.exactMatch(usrname))
    {
        QMessageBox::warning(NULL, tr("提示"), tr("请输入5~9位数的QQ号."));
    }
    else if ( (password != password2) || ( password.size() > 9 ) || ( password.size() == 0 ))
    {
        QMessageBox::warning(NULL, tr("提示"), tr("请输入1~9位数的密码,两次输入要一致."));
    }
    else if ( nickname.size() == 0 )
    {
        QMessageBox::warning(NULL, tr("提示"), tr("昵称不能为空."));
    }
    else
    {
        tcpSocket->abort();
        tcpSocket->connectToHost(QHostAddress(ip),(quint16)port.toUInt());
        //发送注册信息
        QString msgType = "MSG_CLIENT_USER_REGISTER";
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_4_6);
        out << (quint16)0 << msgType << usrname << password << nickname;
        out.device()->seek(0);
        out << (quint16)(block.size() - sizeof(quint16));
        tcpSocket->write(block);



         //this->close();
    }

}

void regdialog::on_ready_Read()
{
    QByteArray block = tcpSocket->readAll();
    QDataStream in(&block, QIODevice::ReadOnly);
    quint16 dataGramSize;
    QString msgType;
    in >> dataGramSize >> msgType;

    if ( "MSG_ID_ALREADY_EXIST" == msgType )
    {
        QMessageBox::warning(NULL, tr("提示"), tr("该号码已被注册."));
    }
    else if ("MSG_REGISTER_SUCCESS" == msgType)
    {
        QMessageBox::information(this, "message", "register success");
        this->close();
    }
 //   else /*if ( "MSG_CLIENT_REGISTER_SUCCESS" == msgType )*/
  //  {
  //      QString msgType = "MSG_CLIENT_REGISTER_SUCCESS";
  //      QByteArray block;
   //     QDataStream out(&block, QIODevice::WriteOnly);
  //      out.setVersion(QDataStream::Qt_4_6);
    //    out << (quint16)0 << msgType;
    //    out.device()->seek(0);
    //    out << (quint16)(block.size() - sizeof(quint16));
    //     tcpSocket->write(block);
        //QUdpSocket *udpSocket = new QUdpSocket(this);
        //udpSocket->writeDatagram(block.data(), block.size(), QHostAddress(ip), (quint16)port.toUInt()+1);
  //  }
}

void regdialog::on_cancelButton_clicked()
{
    this->close();
}

void regdialog::mousePressEvent(QMouseEvent *event)
{
    this->windowPos = this->pos();
    this->mousePos = event->globalPos();
   this->dPos = mousePos - windowPos;

}

void regdialog::mouseMoveEvent(QMouseEvent *event)
{
      this->move(event->globalPos() - this->dPos);
}
