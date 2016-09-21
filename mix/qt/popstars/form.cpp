#include "form.h"
#include "ui_form.h"

Form::Form(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Form)
{
    ui->setupUi(this);
    this->setWindowFlags(Qt::FramelessWindowHint);
    ui->label->setStyleSheet("border-image: url(:/Images/greenStone.png);");
    ui->label_2->setText("Congratuations!");
    ui->label_3->setText("Welcome to next level");
}

Form::~Form()
{
    delete ui;
}

void Form::on_pushButton_clicked()
{
    emit accepted();
    this->hide();
}
