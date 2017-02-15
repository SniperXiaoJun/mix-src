#include "login.h"
#include "ui_login.h"
#include <QMotifStyle>

#include <QPlastiqueStyle>

login::login(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::login)
{
    ui->setupUi(this);

    tcpSocket = new QTcpSocket(this);

    ip.clear();
    port.clear();
    setFlag = true;
    setFlagpwd = true;
    this->resize(390, 350);
    this->setWindowTitle("QQ");
    this->ui->cancelpushButton->setStyle(new QPlastiqueStyle);
    connect(tcpSocket, SIGNAL(readyRead()), this, SLOT(on_ready_Read()));

}

login::~login()
{
    delete ui;
}
void login::mousePressEvent(QMouseEvent *event)
{
    this->windowPos = this->pos();
    this->mousePos = event->globalPos();
    this->dPos = mousePos - windowPos;
}
void login::mouseMoveEvent(QMouseEvent *event)
{
    this->move(event->globalPos() - this->dPos);
}

void login::changeEvent(QEvent *e)
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

//设置服务器端口
void login::on_setButton_clicked()
{
    if (setFlag)
    {
        this->resize(390, 600);
        ui->iplineEdit->setText("192.168.1.101");
        ui->portlineEdit->setText("8888");
        setFlag =false;
    }
    else
    {
        this->resize(390, 600);
        setFlag = true;
    }
}

//登录
void login::on_loginButton_clicked()
{
    if (ip.isEmpty() || port.isEmpty())
    {
        QMessageBox::warning(NULL, tr("提示"), tr("请先设置IP和端口"));
    }
    else
    {
         usrname = ui->usrnamelineEdit->text().trimmed();
         password = ui->passwordlineEdit->text().trimmed();


        QRegExp rx("^[1-9]{1,2}[0-9]{4,7}$");
        rx.setPatternSyntax(QRegExp::RegExp);
        if (!rx.exactMatch(usrname))
        {
            QMessageBox::warning(NULL, tr("提示"), tr("请输入5~9位数的QQ号."));
        }
        else
        {
            tcpSocket->abort();
            tcpSocket->connectToHost(QHostAddress(ip), (quint16)port.toUInt());
            QString msgType = "MSG_USER_LOGIN";
            QByteArray block;
            QDataStream out(&block, QIODevice::WriteOnly);
            out.setVersion(QDataStream::Qt_4_6);
            out << (quint16)0 << msgType << usrname << password;
            out.device()->seek(0);
            out << (quint16)(block.size() - sizeof(quint16));
            tcpSocket->write(block);
        }
    }
}

//注册按钮
void login::on_regButton_clicked()
{
    if ( ip.isEmpty() || port.isEmpty() )
    {
       QMessageBox::warning(NULL, tr("提示"), tr("请先设置IP和端口."));
    }
    else
    {
        reg = new regdialog(ip, port);
        reg->setWindowFlags(Qt::FramelessWindowHint);
        reg->setAttribute(Qt::WA_TranslucentBackground);
        reg->show();
        reg->move(600,100);
    }
}

void login::on_findpwdButton_clicked()
{
    ip = ui->iplineEdit->text().trimmed();
    port = ui->portlineEdit->text().trimmed();

    QRegExp rxIp("\\d+\\.\\d+\\.\\d+\\.\\d+");
    QRegExp rxPort(("[1-9]\\d{3,4}"));
    rxIp.setPatternSyntax(QRegExp::RegExp);
    rxPort.setPatternSyntax(QRegExp::RegExp);

    if ( !rxPort.exactMatch(port) ||  !rxIp.exactMatch(ip) )
    {
        ip.clear();
        port.clear();
        QMessageBox::critical( NULL, tr("提示"), tr("请输入正确的IP和端口.") );
    }
    else
    {
        if (setFlagpwd == true)
        {
            this->resize(650, 350);
            setFlagpwd = false;
        }
        else
        {
            this->resize(650, 350);
            setFlagpwd = true;
        }
    }
}

void login::on_submitpushButton_clicked()
{
    ip = ui->iplineEdit->text().trimmed();
    port = ui->portlineEdit->text().trimmed();

    QRegExp rxIp("\\d+\\.\\d+\\.\\d+\\.\\d+");
    QRegExp rxPort(("[1-9]\\d{3,4}"));
    rxIp.setPatternSyntax(QRegExp::RegExp);
    rxPort.setPatternSyntax(QRegExp::RegExp);

    if ( !rxPort.exactMatch(port) ||  !rxIp.exactMatch(ip) )
    {
        ip.clear();
        port.clear();
        QMessageBox::critical( NULL, tr("提示"), tr("请输入正确的IP和端口.") );
    }
    else
    {
        this->resize(390, 350);
        setFlag = true;
    }

}

void login::on_cancelpushButton_clicked()
{
    this->resize(390, 350);
    setFlag = true;
}

void login::on_ready_Read()
{
    QByteArray block = tcpSocket->readAll();
    QDataStream in(&block, QIODevice::ReadOnly);     //QDataStream in(tcpSocket);
    quint16 dataGramSize;
    QString msgType;
    in >> dataGramSize >> msgType;
//QMessageBox::information(NULL, tr("提示"), tr("客户端收信息"));
    if ( "MSG_ID_NOTEXIST" == msgType )
   {
       QMessageBox::warning(NULL, tr("提示"), tr("该号码不存在，请先注册."));
       ui->usrnamelineEdit->clear();
       ui->passwordlineEdit->clear();
   }
    else if ( "MSG_PWD_ERROR" == msgType )
    {
           QMessageBox::information(NULL, tr("提示"), tr("密码错误."));
           ui->usrnamelineEdit->clear();


    }
    else if ( "MSG_LOGIN_ALREADY" == msgType )
    {
           QMessageBox::information(NULL, tr("提示"), tr("请不要重复登录."));
           ui->usrnamelineEdit->clear();
           ui->passwordlineEdit->clear();
           //this->close();
    }
    else if ( "MSG_LOGIN_SUCCESS" == msgType)
    {
            qqpanel = new panel(usrname, ip, port);
            qqpanel->setWindowTitle(tr("QQcopy"));
            qqpanel->setWindowFlags(Qt::FramelessWindowHint);
            qqpanel->setAttribute(Qt::WA_TranslucentBackground);
            qqpanel->show();
            this->close();
    }
   /* else if ("MSG_CLIENT_FIND_PWD" == msgType)
    {
        QString pwd;
            in >>  pwd;
            QMessageBox::information(NULL, tr("你的密码"), pwd);

    }*/


}

void login::on_findpwdsubmitButton_clicked()
{
    this->resize(390, 350);
     QMessageBox::information( NULL, tr("提示"), tr("密码已发到您的邮箱.") );

  /*  tcpSocket = new QTcpSocket(this);

    ip = ui->iplineEdit->text().trimmed();
    port = ui->portlineEdit->text().trimmed();

    QRegExp rxIp("\\d+\\.\\d+\\.\\d+\\.\\d+");
    QRegExp rxPort(("[1-9]\\d{3,4}"));
    rxIp.setPatternSyntax(QRegExp::RegExp);
    rxPort.setPatternSyntax(QRegExp::RegExp);

    if ( !rxPort.exactMatch(port) ||  !rxIp.exactMatch(ip) )
    {
        ip.clear();
        port.clear();
        QMessageBox::critical( NULL, tr("提示"), tr("请输入正确的IP和端口.") );
    }

    connect(tcpSocket, SIGNAL(readyRead()), this, SLOT(on_ready_Read()));

    QString findpwd = ui->findpwdlineEdit->text().trimmed();

    if ( findpwd.size() == 0 )
    {
        QMessageBox::warning(NULL, tr("提示"), tr("QQ号不能为空."));
    }
    else
    {
        tcpSocket->abort();
        tcpSocket->connectToHost(QHostAddress(ip),(quint16)port.toUInt());

        QString msgType = "MSG_CLIENT_FIND_PWD";
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_4_6);
        out << (quint16)0 << msgType << usrname << password << nickname;
        out.device()->seek(0);
        out << (quint16)(block.size() - sizeof(quint16));
        tcpSocket->write(block);*/

}
