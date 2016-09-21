#ifndef FAILEDFORM_H
#define FAILEDFORM_H

#include <QDialog>
#include<QDebug>

namespace Ui {
    class failedForm;
}

class failedForm : public QDialog
{
    Q_OBJECT

public:
    explicit failedForm(QString& ,QWidget *parent = 0);
//    void setDuration(int num){duration=num;};
    Ui::failedForm *ui;
    ~failedForm();
signals:
    void readyStore();
private slots:
    void on_pushButton_clicked();
    void on_pushButton_2_clicked();
private:


//    int duration;
    QString &name;
//    int
};

#endif // FAILEDFORM_H
