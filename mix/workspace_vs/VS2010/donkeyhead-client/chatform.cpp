#include "chatform.h"
#include "ui_chatform.h"

chatform::chatform(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::chatform)
{
    ui->setupUi(this);
}

chatform::chatform(QString usrname, QString peerIp, QString peerPort, QUdpSocket *udpSocket):ui(new Ui::chatform)
{
    this->usrname = usrname;
    this->serverIp = peerIp;
    this->serverPort = peerPort;
    this->udpSocket = udpSocket;
    ui->setupUi(this);
}

chatform::~chatform()
{
    delete ui;
}

void chatform::changeEvent(QEvent *e)
{
    QWidget::changeEvent(e);
    switch (e->type()) {
    case QEvent::LanguageChange:
        ui->retranslateUi(this);
        break;
    default:
        break;
    }
}

void chatform::displayText(QString nickname, QString usrname, QString text)
{
    QListWidgetItem *displayItem = new QListWidgetItem(nickname + "(" + usrname + ") :\n" + text + "\n");
    ui->listWidget->addItem(displayItem);
}

void chatform::on_sendButton_clicked()
{
    QString sendText = ui->textEdit->toPlainText();
       if(!sendText.isEmpty())
       {

           QString windowTitle = this->windowTitle().replace("].","");
           QString toId = QString(windowTitle.split("[").at(1));
           QString msgType = "MSG_CLIENT_CHAT";
           QByteArray block;
           QDataStream out(&block, QIODevice::WriteOnly);
           out.setVersion(QDataStream::Qt_4_6);
           out << (quint16)0 << msgType << usrname << toId << sendText;
           out.device()->seek(0);

           out << (quint16)(block.size() - sizeof(quint16));

           udpSocket->writeDatagram(block.data(), block.size(), QHostAddress(serverIp), (quint16)serverPort.toUInt()+1);
          ui->listWidget->addItem("I say :\n" + sendText + "\n");
       }
       ui->textEdit->clear();
}

void chatform::closeEvent(QCloseEvent *e)
{
    ui->listWidget->clear();
    ui->textEdit->clear();
}


void chatform::on_pushButton_clicked()
{
  ui->listWidget->setStyleSheet("background-image: url(:/new/prefix1/6.jpg);");
}

void chatform::on_pushButton_2_clicked()
{
    ui->listWidget->setStyleSheet("background-image: url(:/new/prefix1/2.jpg);");
}

void chatform::on_pushButton_3_clicked()
{
    ui->listWidget->setStyleSheet("background-image: url(:/new/prefix1/1.jpg);");
}
void chatform::mousePressEvent(QMouseEvent *event)
{
    this->windowPos = this->pos();
            this->mousePos = event->globalPos();
            this->dPos = mousePos - windowPos;
}

void chatform::mouseMoveEvent(QMouseEvent *event)
{
     this->move(event->globalPos() - this->dPos);

}

void chatform::on_pushButton_4_clicked()
{
    this->close();
}
