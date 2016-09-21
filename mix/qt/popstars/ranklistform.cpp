#include "ranklistform.h"
#include "ui_ranklistform.h"

ranklistForm::ranklistForm(QWidget *parent,bool &opened) :
    QDialog(parent),
    ui(new Ui::ranklistForm),
    is_opened(opened)
{
    ui->setupUi(this);
    opened=true;
    this->setWindowFlags(Qt::FramelessWindowHint);
    ui->label->setFixedSize(40,40);
    ui->label->setStyleSheet("background-image: url(:/Images/blueStone.png);");
    ui->label_2->setText("Ranklist");
    //ui->label_3->setText("Please enter your name:");
    QSqlDatabase db=QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("star");
    db.open();
    QSqlQuery query;
    //query.exec("drop table record");
    if(!query.exec("select *from record order by score desc"))return;
    QVector<QString> nameList;
    QVector<QString> duraList;
    QVector<QString> levelList;
    QVector<QString> scoreList;
    while(query.next())
    {
        nameList.push_back(query.value(0).toString());
        duraList.push_back(query.value(1).toString());
        levelList.push_back(query.value(2).toString());
        scoreList.push_back(query.value(3).toString());
    }
    db.close();
    if(nameList.size()>0)
        ui->name_0->setText(nameList[0]);
    if(nameList.size()>1)
        ui->name_1->setText(nameList[1]);
    if(nameList.size()>2)
        ui->name_2->setText(nameList[2]);
    if(nameList.size()>3)
        ui->name_3->setText(nameList[3]);
    if(nameList.size()>4)
        ui->name_4->setText(nameList[4]);

    if(duraList.size()>0)
        ui->dura_0->setText(duraList[0]);
    if(duraList.size()>1)
        ui->dura_1->setText(duraList[1]);
    if(duraList.size()>2)
        ui->dura_2->setText(duraList[2]);
    if(duraList.size()>3)
        ui->dura_3->setText(duraList[3]);
    if(duraList.size()>4)
        ui->dura_4->setText(duraList[4]);

    if(levelList.size()>0)
        ui->level_0->setText(levelList[0]);
    if(levelList.size()>1)
        ui->level_1->setText(levelList[1]);
    if(levelList.size()>2)
        ui->level_2->setText(levelList[2]);
    if(levelList.size()>3)
        ui->level_3->setText(levelList[3]);
    if(levelList.size()>4)
        ui->level_4->setText(levelList[4]);

    if(scoreList.size()>0)
        ui->score_0->setText(scoreList[0]);
    if(scoreList.size()>1)
        ui->score_1->setText(scoreList[1]);
    if(scoreList.size()>2)
        ui->score_2->setText(scoreList[2]);
    if(scoreList.size()>3)
        ui->score_3->setText(scoreList[3]);
    if(scoreList.size()>4)
        ui->score_4->setText(scoreList[4]);
}
void ranklistForm::mousePressEvent(QMouseEvent *e)
{
    this->close();
    is_opened=false;
}

ranklistForm::~ranklistForm()
{
    delete ui;
}
