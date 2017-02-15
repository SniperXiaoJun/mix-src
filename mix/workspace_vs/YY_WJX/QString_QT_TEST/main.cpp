
#include "QString_QT_TEST.h"

#include <QtGui>
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QString_QT_TEST w;
    w.showMaximized();
    return a.exec();
}
