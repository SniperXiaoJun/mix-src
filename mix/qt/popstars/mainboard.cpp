#include "mainboard.h"
#include "ui_mainboard.h"
#include <ctime>
#include <cstdlib>
#include <QtMath>

#include <QMessageBox>

using std::swap;

mainBoard::mainBoard(QWidget *parent) :
    QWidget(parent),
    Ui::mainBoard(*new Ui::mainBoard)
{
    setupUi(this);

    //this->setWindowFlags(Qt::FramelessWindowHint);
    //this->widget->setStyleSheet("background-color: rgb(255, 255, 255);");


    this->widget->setStyleSheet("border-color: #FFFFFF");

    init();
}

int mainBoard::circleTick(int circle_round, int level)
{
    int circle_tick = 0;

    if (0 == level % circle_round)
    {
        circle_tick = 0;
    }
    else if (0 == ((level % circle_round) - (circle_round/2)))
    {
         for(int i = 1 ; i <= (circle_round/2); i++)
         {
             circle_tick += i - (circle_round/2);
         }
    }
    else if (((level % circle_round) - (circle_round/2)) < 0)
    {
         for(int i = 1 ; i <= level % circle_round; i++)
         {
             circle_tick += i - (circle_round/2);
         }
    }
    else if(((level % circle_round) - (circle_round/2)) > 0)
    {
        for(int i = 1 ; i <= (circle_round/2); i++)
        {
            circle_tick += i - (circle_round/2);
        }

        for(int i = 1 ; i <= ((level % circle_round) - (circle_round/2)); i++)
        {
            circle_tick += i;
        }
    }
    else
    {
        circle_tick = 0;
    }

    return circle_tick;
}

void mainBoard::init()
{
    starSize = this->widget->width() < this->widget->height() ? this->widget->width()/10 : this->widget->height()/10;
    minimumX = (this->widget->width() % starSize) / 2;
    minimumY = (this->widget->height() % starSize) / 2;
    maxRow = this->widget->height() / starSize;
    maxColumn = this->widget->width() / starSize;


    circle_round = 8;   // 一轮8次
    fillFound = 0;
    score = 0;
    level = 1;
    rankListOpened = false;
    scoreSaved = false;


    leaveStarNum = maxRow*maxColumn;
    //baseScore =maxRow*maxColumn * 5 * (qPow(2,level) -1);
    baseScore =maxRow*maxColumn * 25 * level;
    targetScore = baseScore + (maxRow*maxColumn * circleTick(circle_round,level) * 5);

    for(int i=0;i<maxRow;i++)
    {
        memset(stars[i],0,sizeof(stars[i]));
    }

    this->label_levelText->setText(QString::number(level));
    this->label_targetText->setText(QString::number(targetScore));
    this->label_scoreText->setText(QString::number(score));

    label_selectText->setText(QString::number(0));
    label_selectScoreText->setText(QString::number(0));
    label_leftText->setText(QString::number(leaveStarNum));
}


void mainBoard::clearBoard()
{
    leaveStarNum=maxRow*maxColumn;
    fillFound=0;
    //baseScore =maxRow*maxColumn * 5 * (qPow(2,level) -1);
    baseScore =maxRow*maxColumn * 25 * level;
    targetScore = baseScore + (maxRow*maxColumn * circleTick(circle_round,level) * 5);

    this->label_levelText->setText(QString::number(level));
    this->label_targetText->setText(QString::number(targetScore));
    this->label_scoreText->setText(QString::number(score));


    label_selectText->setText(QString::number(0));
    label_selectScoreText->setText(QString::number(0));
    label_leftText->setText(QString::number(leaveStarNum));

    for(int i=0;i<maxRow;i++)
    {
        for(int j=0;j<maxColumn;j++)
        {
            if(stars[i][j]!=NULL)
            {
                delete stars[i][j];
                stars[i][j]=0;
            }
        }
    }
}

void mainBoard::startGame()
{
    level = 1;

    clearBoard();

    init();

    initBoard();

    timer.restart();
}
void mainBoard::nextLevel()
{
    level++;

    clearBoard();

    initBoard();
}

void mainBoard::initBoard()
{
    int topx,topy;

    for(int row=0;row<maxRow;row++)
    {
        for(int col=0;col<maxColumn;col++)
        {
            stars[row][col]=new MixButtonStar(this->widget,types[row][col]=rand()%5, starSize, starSize);


           connect(stars[row][col],SIGNAL(signalStarActive(QWidget *)), this, SLOT(onSelectStarActive(QWidget *)));


         //   connect(stars[row][col],SIGNAL(clicked()), this, SLOT(onStarButtonActive()));

            topx=minimumX+col*starSize;
            topy=minimumY+row*starSize;
            stars[row][col]->setGeometry(topx,topy,topx+starSize,topy+starSize);
            stars[row][col]->show();
        }
    }
}

void mainBoard::onStarButtonActive()
{
    if (QPushButton* btn = dynamic_cast<QPushButton*>(sender())){
        onSelectStarActive(btn);
    }
    else{

    }
}

void mainBoard::onSelectStarActive(QWidget * widgetItem)
{
    int x= widgetItem->x();
    int y= widgetItem->y();

    qDebug()<<x<<y<<"    position";
    if(x<minimumX||x>minimumX+maxColumn*starSize||y<minimumY||y>minimumY+maxRow*starSize){qDebug()<<"err1";return;}
    if(stars[(y-minimumY)/starSize][(x-minimumX)/starSize]==NULL)
    {
        return;
    }

    if(1 == stars[(y-minimumY)/starSize][(x-minimumX)/starSize]->getState())
    {
        handleStar((y-minimumY)/starSize,(x-minimumX)/starSize,-1);

        if(fillFound<=0)return;
        leaveStarNum-=fillFound;
        //score+=(fillFound)*(fillFound)*5*qPow(level, 2);

        score+=(fillFound)*(fillFound)*5;

        label_scoreText->setText(QString::number(score));

        // add left select and select score
        label_selectText->setText(QString::number(fillFound));
        label_selectScoreText->setText(QString::number((fillFound)*(fillFound)*5));
        label_leftText->setText(QString::number(leaveStarNum));

        shuffleDown();
        victoryCheck();
    }
    else
    {
        for(int i=0;i<maxRow;i++)
        {
            for(int j=0;j<maxColumn;j++)
            {
                if(stars[i][j]!=NULL)
                {
                    stars[i][j]->setState(0);
                }
            }
        }

        activeRoundStars((y-minimumY)/starSize,(x-minimumX)/starSize,-1);

        if(fillFound<=0)return;

        label_scoreText->setText(QString::number(score));

        // add left select and select score
        label_selectText->setText(QString::number(fillFound));
        label_selectScoreText->setText(QString::number((fillFound)*(fillFound)*5));
        label_leftText->setText(QString::number(leaveStarNum));
    }
}

void mainBoard::mousePressEvent(QMouseEvent *e)
{
    int x=e->x() - this->widget->pos().x();
    int y=e->y() - this->widget->pos().y();
    qDebug()<<x<<y<<"    position";
    if(x<minimumX||x>minimumX+maxColumn*starSize||y<minimumY||y>minimumY+maxRow*starSize){qDebug()<<"err1";return;}
    if(stars[(y-minimumY)/starSize][(x-minimumX)/starSize]==NULL)
    {
        return;
    }

    if(1 == stars[(y-minimumY)/starSize][(x-minimumX)/starSize]->getState())
    {
        handleStar((y-minimumY)/starSize,(x-minimumX)/starSize,-1);

        if(fillFound<=0)return;
        leaveStarNum-=fillFound;
        //score+=(fillFound)*(fillFound)*5*qPow(level, 2);

        score+=(fillFound)*(fillFound)*5;

        label_scoreText->setText(QString::number(score));

        // add left select and select score
        label_selectText->setText(QString::number(fillFound));
        label_selectScoreText->setText(QString::number((fillFound)*(fillFound)*5));
        label_leftText->setText(QString::number(leaveStarNum));

        shuffleDown();
        victoryCheck();
    }
    else
    {
        for(int i=0;i<maxRow;i++)
        {
            for(int j=0;j<maxColumn;j++)
            {
                if(stars[i][j]!=NULL)
                {
                    stars[i][j]->setState(0);
                }
            }
        }

        activeRoundStars((y-minimumY)/starSize,(x-minimumX)/starSize,-1);

        if(fillFound<=0)return;

        label_scoreText->setText(QString::number(score));

        // add left select and select score
        label_selectText->setText(QString::number(fillFound));
        label_selectScoreText->setText(QString::number((fillFound)*(fillFound)*5));
        label_leftText->setText(QString::number(leaveStarNum));
    }
}
void mainBoard::handleStar(int row,int col,int type)
{

    if(stars[row][col]==NULL)return ;
    bool first=false;
    if(type==-1)
    {
        first=true;
        type=types[row][col];
        fillFound=0;
        memset(used,0,sizeof(used));
    }
    if(col>=maxColumn||col<0||row>=maxRow||row<0)return;
    if(used[row*maxColumn+col]||(!first&&type!=types[row][col]))return;
    used[row*maxColumn+col]=true;
    handleStar(row+1,col,type);
    handleStar(row,col+1,type);
    handleStar(row,col-1,type);
    handleStar(row-1,col,type);
    if(first==true&&fillFound==0)return;
    delete stars[row][col];
    stars[row][col]=NULL;
    fillFound+=1;
}

void mainBoard::activeRoundStars(int row,int col,int type)
{

    if(stars[row][col]==NULL)return ;
    bool first=false;
    if(type==-1)
    {
        first=true;
        type=types[row][col];
        fillFound=0;
        memset(used,0,sizeof(used));
    }
    qDebug()<<"col"<<col;
    qDebug()<<"row"<<row;
    qDebug()<<"used[row*maxColumn+col]"<<used[row*maxColumn+col];
    qDebug()<<"first"<<first;
    qDebug()<<"type"<<type;
    qDebug()<<"types[row][col]"<<types[row][col];

    if(col>=maxColumn||col<0||row>=maxRow||row<0)return;
    if(used[row*maxColumn+col]||(!first&&type!=types[row][col]))return;
    used[row*maxColumn+col]=true;
    activeRoundStars(row+1,col,type);
    activeRoundStars(row,col+1,type);
    activeRoundStars(row,col-1,type);
    activeRoundStars(row-1,col,type);
    if(first==true&&fillFound==0)return;

    stars[row][col]->setState(1);

    fillFound+=1;
}


void mainBoard::shuffleDown()
{
    int newtopx,newtopy;
    int dist;
    for(int col=0;col<maxColumn;col++)
    {
        dist=0;
        for(int row=maxRow-1;row>-1;row--)
        {
            if(stars[row][col]==NULL)++dist;
            else
            {
                if(dist>0)
                {
                    newtopx=minimumX+col*starSize;
                    newtopy=minimumY+(row+dist)*starSize;
                    stars[row][col]->setGeometry(newtopx,newtopy,newtopx+starSize,newtopy+starSize);

                    swap(stars[row+dist][col],stars[row][col]);
                    swap(types[row+dist][col],types[row][col]);
                }
            }
        }
    }
    dist=0;
    for(int col=0;col<maxColumn;col++)
    {
        if(stars[maxRow-1][col]==NULL)
        {
            dist+=1;
        }
        else
        {
            if(dist>0)
            {
                for(int row=maxRow-1;row>-1;row--)
                {
                    if(stars[row][col]==NULL)continue;
                    newtopx=minimumX+(col-dist)*starSize;
                    newtopy=minimumY+row*starSize;
                    stars[row][col]->setGeometry(newtopx,newtopy,newtopx+starSize,newtopy+starSize);

                    swap(types[row][col-dist],types[row][col]);
                    swap(stars[row][col-dist],stars[row][col]);

                }
            }
        }

    }
}


void mainBoard::victoryCheck()
{
    bool finish=!moveCheck(maxRow-1,0,-1);

    if(finish)
    {
        if (leaveStarNum < (maxRow > maxColumn ? maxRow:maxColumn))
        {
             //score += qPow(((maxRow > maxColumn ? maxRow:maxColumn) - leaveStarNum),2) * 100; // max=10*10*100 = 10000
             //score += qPow(2,((maxRow > maxColumn ? maxRow:maxColumn) - leaveStarNum)) * 100; // max=1024*100 = 102400
        }

        int leftScore = 0 ;

        for(int i = 0 ; i < (maxRow > maxColumn ? maxRow:maxColumn) - leaveStarNum; i++)
        {
            leftScore += (i+1) * 100;
        }

        QMessageBox::information(this,"LeftStar","Left Stars:" + QString::number(leaveStarNum) + "\nLeft Stars's Score:" + QString::number(leftScore));

        score += leftScore;

        label_scoreText->setText(QString::number(score));

        passed=new Form(this);
        passed->setWindowFlags(Qt::WindowStaysOnTopHint);
        passed->setGeometry(this->width()/4, this->height()/4, this->width()/2,this->height()/2);
        passed->hide();

        failed=(new failedForm(name,this));
        failed->setWindowFlags(Qt::WindowStaysOnTopHint);
        failed->setGeometry(this->width()/4, this->height()/4, this->width()/2,this->height()/2);
        failed->hide();

        connect(passed,SIGNAL(accepted()),this,SLOT(nextLevel()));
        connect(failed,SIGNAL(readyStore()),this,SLOT(store()));
        if(score>=targetScore)
        {
            passed->show();
        }
        else
        {
            failed->show();
            duration=timer.elapsed();

            qDebug()<<timer.elapsed()<<"time";
        }
    }
}
bool mainBoard::moveCheck(int row,int col,int type)
{
    if(row<0||row>=maxRow||col<0||col>=maxColumn)return false;
    if(stars[row][col]==NULL)return false;
    if(type==types[row][col]){qDebug()<<"*********"<<row<<col;return true;}
    ///////////////////////////////////////////////
    return moveCheck(row-1,col,types[row][col])||moveCheck(row,col+1,types[row][col]);
}
void mainBoard::store()
{
    //qDebug()<<name;
    saveInfoToDb(name,duration/1000,level,score);
}

void mainBoard::saveInfoToDb(QString name, int duration, int level, int score)
{
    QSqlDatabase db=QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("star");
    qDebug()<<db.open();
    QSqlQuery query;
    qDebug()<<query.exec("create table record ("
                      "name varchar(10) primary key, "
                         "duration int,level int,"
                         "score int)");

    qDebug()<<query.prepare("insert into record values(?,?,?,?)");
    query.addBindValue(name);
    query.addBindValue(duration);
    query.addBindValue(level);
    query.addBindValue(score);
    if(!query.exec())
    {
        query.prepare("select score from record where name = ?");
        query.addBindValue(name);
        query.exec();
        query.last();
        int preScore=query.value(4).toInt();
        if(score>preScore)
        {
            query.prepare("delete from record where name=?");
            query.addBindValue(name);
            query.exec();
            qDebug()<<query.prepare("insert into record values(?,?,?,?)");
            query.addBindValue(name);
            query.addBindValue(duration);
            query.addBindValue(level);
            query.addBindValue(score);
            query.exec();
        }
    }
    db.close();
    scoreSaved=true;
}

mainBoard::~mainBoard()
{
}

void mainBoard::on_startButton_clicked()
{
    startGame();
}

void mainBoard::on_pushButton_clicked()
{
    if(rankListOpened)return;
    ranklistForm *pf=new ranklistForm(this,rankListOpened);
    pf->setGeometry(this->width()/4, this->height()/4, this->width()/2,this->height()/2);
    pf->show();
}

void mainBoard::closeEvent(QCloseEvent *)
{
    duration=timer.elapsed()/1000;
    if(!scoreSaved)
    saveInfoToDb("Anonimous",duration,level,score);
    exit(0);
}

void mainBoard::on_quitButton_clicked()
{
    duration=timer.elapsed()/1000;
    if(!scoreSaved)
    saveInfoToDb("Anonimous",duration,level,score);
    exit(0);
}
