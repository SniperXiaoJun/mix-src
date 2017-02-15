/****************************************************************************
**
** Date    : 2010-07-07
** Author  : furtherchan
** E-Mail  : cnsilan@163.com

** If you have any questions , please contact me
**
****************************************************************************/

#include <QtGui/QApplication>
//#include <QTextcodec>
#include "daemon.h"

int main(int argc, char *argv[])
{
    QApplication::setStyle("Plastique");
    QApplication a(argc, argv);

    //support chinese character set
    QTextCodec::setCodecForCStrings(QTextCodec::codecForName("GB2312"));
    QTextCodec::setCodecForLocale(QTextCodec::codecForName("GB2312"));
    QTextCodec::setCodecForTr(QTextCodec::codecForName("GB2312"));

    Daemon w;

    w.setWindowTitle("LV-QQ.Server");
    w.resize(600,600);
    w.setWindowOpacity(1);
    w.setWindowFlags(Qt::FramelessWindowHint);
    w.setAttribute(Qt::WA_TranslucentBackground);
    w.show();

    return a.exec();
}
