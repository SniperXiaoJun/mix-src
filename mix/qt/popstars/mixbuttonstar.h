#ifndef MIXBUTTONSTAR_H
#define MIXBUTTONSTAR_H

#include <QLabel>


class MixButtonStar : public QLabel
{
    Q_OBJECT
public:
    MixButtonStar(QWidget *parent = 0,int type=0, int size_x = 40, int size_y = 40, int state = 0);


    void setState(int state);
    int getState();
signals:

    void signalStarActive(QWidget * widget);

public slots:

    void onStarActive(bool bCheck);

private:
    int m_iState;
    int m_iType;

};

#endif // MIXBUTTONSTAR_H
