#include "star.h"

Star::Star(QWidget *parent,int type, int size_x,int size_y) :
    QLabel(parent)
{
    this->setFixedSize(size_x,size_y);
    if(type==0)
    {
        //this->setIcon(* new QIcon(":Images/blue_blank.png"));
        this->setStyleSheet("border-image: url(:/Images/blue_blank.png);");
    }
    else if(type==1)
    {
        this->setStyleSheet("border-image: url(:/Images/purple_blank.png);");
    }
    else if(type==2)
    {
        this->setStyleSheet("border-image: url(:/Images/yellow_blank.png);");
    }
    else if(type==3)
    {
        this->setStyleSheet("border-image: url(:/Images/pink_blank.png);");
    }
    else
    {
        this->setStyleSheet("border-image: url(:/Images/green_blank.png);");
    }
}
