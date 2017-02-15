
#include "CInbox.h"

#include <QtGui>
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    CInbox w;
    w.showMaximized();
    return a.exec();
}
