#ifndef LOGIN_H
#define LOGIN_H

#include <QMainWindow>
#include <QTcpSocket>
#include <QMessageBox>
#include <QHostAddress>
#include <QTextCodec>
#include <QMouseEvent>
#include <QPoint>

#include "regdialog.h"
#include "panel.h"

namespace Ui {
    class login;
}

class login : public QMainWindow {
    Q_OBJECT
public:
    login(QWidget *parent = 0);
    ~login();

protected:
    void changeEvent(QEvent *e);
    void mouseMoveEvent(QMouseEvent *);
    void mousePressEvent(QMouseEvent *);

private:
    Ui::login *ui;
    QPoint windowPos;
    QPoint mousePos;
    QPoint dPos;

    QString ip;
    QString port;
    QString usrname;
    QString password;

    QTcpSocket *tcpSocket;
    regdialog *reg;
    bool setFlag;
    bool setFlagpwd;
    panel *qqpanel;

private slots:

    void on_findpwdsubmitButton_clicked();
    void on_cancelpushButton_clicked();
    void on_submitpushButton_clicked();
    void on_findpwdButton_clicked();
    void on_regButton_clicked();
    void on_setButton_clicked();
    void on_loginButton_clicked();
    void on_ready_Read();
};

#endif // LOGIN_H
