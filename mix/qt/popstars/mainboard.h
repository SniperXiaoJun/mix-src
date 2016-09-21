#ifndef MAINBOARD_H
#define MAINBOARD_H

#include <QWidget>
#include "ui_mainboard.h"
#include "MixButtonStar.h"
#include <QLayout>
#include <QMouseEvent>
#include <QDebug>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include "form.h"
#include "failedform.h"
#include "ranklistform.h"
#include <cstdio>
#include <QTime>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>

namespace Ui {
    class mainBoard;
}

class mainBoard : public QWidget,Ui::mainBoard
{
    Q_OBJECT
    friend class failedForm;

public:
    explicit mainBoard(QWidget *parent = 0);
    ~mainBoard();
    void startGame();
    void mousePressEvent(QMouseEvent *e);
    void handleStar(int ,int ,int);
    void activeRoundStars(int row,int col,int type);
    void shuffleDown();
    void victoryCheck();
    bool moveCheck(int,int,int);
    void clearBoard();
    void initBoard();
    void closeEvent(QCloseEvent *);
    void saveInfoToDb(QString name,int duration,int level,int score);
    void init();
    int circleTick(int circle_round, int level);


protected:
    int minimumX;
    int minimumY;
    int maxRow;
    int maxColumn;
    int starSize;
    MixButtonStar* stars[255][255];
    int types[255][255];
    int leaveStarNum;
    int fillFound;
    int score;
    bool used[255 * 255];
    int level;
    int baseScore;
    int targetScore;
    Form *passed;
    failedForm *failed;
    QTime timer;
    int duration;
    QString name;
    bool rankListOpened;
    bool scoreSaved;
    int circle_round;

public slots:
    void nextLevel();
    void store();
    void onStarButtonActive();

    void on_startButton_clicked();
    void on_pushButton_clicked();
    void on_quitButton_clicked();
    void onSelectStarActive(QWidget * widgetItem);
};

#endif // MAINBOARD_H
