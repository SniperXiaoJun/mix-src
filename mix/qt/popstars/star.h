#ifndef STAR_H
#define STAR_H

#include <QLabel>

class Star : public QLabel
{
    Q_OBJECT
public:
    Star(QWidget *parent = 0,int type=0, int size_x = 40, int size_y = 40);

signals:

public slots:

};

#endif // STAR_H
