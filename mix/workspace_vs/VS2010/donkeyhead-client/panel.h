#ifndef PANEL_H
#define PANEL_H

#include <QMainWindow>
#include <QString>
#include <QUdpSocket>
#include <QByteArray>
#include <QDataStream>
#include <QCloseEvent>
#include <QMessageBox>
#include <QHash>
#include "chatform.h"

namespace Ui {
    class panel;
}

class panel : public QMainWindow {
    Q_OBJECT
public:
    panel(QString usrname, QString ip, QString port, QWidget *parent = 0);
    ~panel();
    void init();

protected:
    void changeEvent(QEvent *e);
    void closeEvent(QCloseEvent *e);
    void mousePressEvent(QMouseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);

private:
    Ui::panel *ui;
    QString ip;
    QString port;
    QString usrname;
    QUdpSocket *udpSocket;
    bool flag;
    QHash<QString,chatform *> chatformHash;
    QPoint windowPos;
    QPoint mousePos;
    QPoint dPos;

private slots:
    void on_pushButton_clicked();
    void on_editButton_clicked();
    void on_usrlistWidget_itemDoubleClicked(QListWidgetItem* item);
    void on_setButton_clicked();
    void on_quitButton_clicked();
    void recvMsg();

};

#endif // PANEL_H
