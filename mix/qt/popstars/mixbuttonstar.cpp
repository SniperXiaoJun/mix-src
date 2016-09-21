#include "mixbuttonstar.h"

MixButtonStar::MixButtonStar(QWidget *parent,int type, int size_x,int size_y, int state):
    QLabel(parent)
{
    this->setFixedSize(size_x,size_y);

    this->setEnabled(false);

    m_iType = type;
    m_iState = state;

    int radius = size_x / 2;

    if (0 != state)
    {
        if(m_iType==0)
        {
            //this->setIcon(* new QIcon(":Images/blue_blank.png"));
            this->setStyleSheet("border-image: url(:/Images/blue_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
        else if(m_iType==1)
        {
            this->setStyleSheet("border-image: url(:/Images/purple_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
        else if(m_iType==2)
        {
            this->setStyleSheet("border-image: url(:/Images/yellow_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
        else if(m_iType==3)
        {
            this->setStyleSheet("border-image: url(:/Images/pink_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
        else
        {
            this->setStyleSheet("border-image: url(:/Images/green_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
    }
    else
    {
        if(m_iType==0)
        {
            //this->setIcon(* new QIcon(":Images/blue_blank.png"));
            this->setStyleSheet("border-image: url(:/Images/blue_blank.png);");
        }
        else if(m_iType==1)
        {
            this->setStyleSheet("border-image: url(:/Images/purple_blank.png);");
        }
        else if(m_iType==2)
        {
            this->setStyleSheet("border-image: url(:/Images/yellow_blank.png);");
        }
        else if(m_iType==3)
        {
            this->setStyleSheet("border-image: url(:/Images/pink_blank.png);");
        }
        else
        {
            this->setStyleSheet("border-image: url(:/Images/green_blank.png);");
        }
    }

    //connect(this,SIGNAL(clicked(bool)), this, SLOT(onStarActive(bool)));
}

void MixButtonStar::onStarActive(bool bCheck)
{
    emit signalStarActive(this);
}

int MixButtonStar::getState()
{
    return m_iState;
}

void MixButtonStar::setState(int state)
{
    m_iState = state;

    int radius = this->width() / 2;

    if (0 != state)
    {
        if(m_iType==0)
        {
            //this->setIcon(* new QIcon(":Images/blue_blank.png"));
            this->setStyleSheet("border-image: url(:/Images/blue_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
        else if(m_iType==1)
        {
            this->setStyleSheet("border-image: url(:/Images/purple_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
        else if(m_iType==2)
        {
            this->setStyleSheet("border-image: url(:/Images/yellow_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
        else if(m_iType==3)
        {
            this->setStyleSheet("border-image: url(:/Images/pink_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
        else
        {
            this->setStyleSheet("border-image: url(:/Images/green_blank.png);border-radius:"+ QString::number(radius) +"px;");
        }
    }
    else
    {
        if(m_iType==0)
        {
            //this->setIcon(* new QIcon(":Images/blue_blank.png"));
            this->setStyleSheet("border-image: url(:/Images/blue_blank.png);");
        }
        else if(m_iType==1)
        {
            this->setStyleSheet("border-image: url(:/Images/purple_blank.png);");
        }
        else if(m_iType==2)
        {
            this->setStyleSheet("border-image: url(:/Images/yellow_blank.png);");
        }
        else if(m_iType==3)
        {
            this->setStyleSheet("border-image: url(:/Images/pink_blank.png);");
        }
        else
        {
            this->setStyleSheet("border-image: url(:/Images/green_blank.png);");
        }
    }

}
