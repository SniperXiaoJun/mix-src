#ifndef FINDPWD_H
#define FINDPWD_H

#include <QDialog>

namespace Ui {
    class findpwd;
}

class findpwd : public QDialog {
    Q_OBJECT
public:
    findpwd(QWidget *parent = 0);
    ~findpwd();

protected:
    void changeEvent(QEvent *e);

private:
    Ui::findpwd *ui;

private slots:
    void on_pushButton_clicked();
};

#endif // FINDPWD_H
