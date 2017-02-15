#ifndef REGDIALOG_H
#define REGDIALOG_H

#include <QDialog>
#include <QTcpSocket>
#include <QMessageBox>
#include <QUdpSocket>
#include <QMouseEvent>

namespace Ui {
    class regdialog;
}

class regdialog : public QDialog {
    Q_OBJECT
public:
    regdialog(QString ip, QString port, QWidget *parent = 0);
    ~regdialog();

protected:
    void changeEvent(QEvent *e);
    void mousePressEvent(QMouseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);

private:
    Ui::regdialog *ui;

    QTcpSocket *tcpSocket;
    QString ip;
    QString port;
    QPoint windowPos;
    QPoint mousePos;
    QPoint dPos;


private slots:
    void on_cancelButton_clicked();
    void on_submitButton_clicked();
    void on_ready_Read();
};

#endif // REGDIALOG_H
