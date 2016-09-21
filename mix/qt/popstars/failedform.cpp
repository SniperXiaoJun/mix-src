#include "failedform.h"
#include "ui_failedform.h"

failedForm::failedForm(QString & n,QWidget *parent) :
    QDialog(parent),
    ui(new Ui::failedForm),name(n)
{
    ui->setupUi(this);
    this->setWindowFlags(Qt::FramelessWindowHint);
    ui->label->setStyleSheet("border-image: url(:/Images/redStone.png);");
    ui->label_2->setText("Game over!");
    ui->label_3->setText("Please enter your name:");
}

failedForm::~failedForm()
{
    delete ui;
}

void failedForm::on_pushButton_clicked()
{
    name=ui->lineEdit->text();
    emit readyStore();
    this->hide();
}

void failedForm::on_pushButton_2_clicked()
{
    this->hide();
}
