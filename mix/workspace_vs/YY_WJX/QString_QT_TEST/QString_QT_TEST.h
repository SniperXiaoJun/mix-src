/****************************************************************************
****************************************************************************/

#ifndef QSTRING_QT_TEST_H
#define QSTRING_QT_TEST_H

#include <QtGui/QMainWindow>
#include "ui_QString_QT_TEST.h"

class QString_QT_TEST : public QMainWindow
{
    Q_OBJECT

public:
	QString_QT_TEST(QWidget *parent = 0);
    ~QString_QT_TEST();
public slots:
    void AddOneLine();

private:
    Ui::QString_QT_TEST ui;
};

#endif // QSTRING_QT_TEST_H
