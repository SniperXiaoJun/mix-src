#include "findpwd.h"
#include "ui_findpwd.h"

findpwd::findpwd(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::findpwd)
{
    ui->setupUi(this);
}

findpwd::~findpwd()
{
    delete ui;
}

void findpwd::changeEvent(QEvent *e)
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

void findpwd::on_pushButton_clicked()
{

}
