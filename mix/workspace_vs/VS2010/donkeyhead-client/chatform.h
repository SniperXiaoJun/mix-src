#ifndef CHATFORM_H
#define CHATFORM_H

#include <QWidget>
#include <QMessageBox>
#include <QUdpSocket>
#include <QListWidgetItem>
#include <QUdpSocket>
#include <QByteArray>
#include <QCloseEvent>
#include <QMainWindow>

namespace Ui {
    class chatform;
}

class chatform : public QDialog {
    Q_OBJECT
public:
    chatform(QWidget *parent = 0);
    chatform(QString usrname, QString peerIp, QString peerPort, QUdpSocket *udpSocket);
    ~chatform();
    void displayText(QString nickname, QString usrname, QString text);

protected:
    void changeEvent(QEvent *e);
    void closeEvent(QCloseEvent *e);
    void mousePressEvent(QMouseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);


private:
    Ui::chatform *ui;
    QString serverIp;
    QString serverPort;
    QString usrname;
    QUdpSocket *udpSocket;
    QPoint windowPos;
        QPoint mousePos;
        QPoint dPos;

private slots:
    //void on_radioButton_clicked(bool checked);
    void on_pushButton_4_clicked();
    void on_pushButton_3_clicked();
    void on_pushButton_2_clicked();
    void on_pushButton_clicked();
    void on_sendButton_clicked();
};

#endif // CHATFORM_H
