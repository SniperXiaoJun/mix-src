#ifndef FORM_H
#define FORM_H

#include <QDialog>

namespace Ui {
    class Form;
}

class Form : public QDialog
{
    Q_OBJECT

public:
    explicit Form(QWidget *parent = 0);
    ~Form();
signals:
    void accepted();

private slots:
    void on_pushButton_clicked();
private:
    Ui::Form *ui;
};

#endif // FORM_H
