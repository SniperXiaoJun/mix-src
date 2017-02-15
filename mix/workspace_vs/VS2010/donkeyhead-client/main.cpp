#include <QtGui/QApplication>
#include "login.h"

int main(int argc, char *argv[])
{
    QApplication::setStyle("cleanlooks");
    QApplication a(argc, argv);
    QTextCodec::setCodecForCStrings(QTextCodec::codecForName("GB2312"));
    QTextCodec::setCodecForLocale(QTextCodec::codecForName("GB2312"));
    QTextCodec::setCodecForTr(QTextCodec::codecForName("GB2312"));
    login w;
    w.setWindowTitle("ClientLogin");


    w.setWindowOpacity(1);
    w.setWindowFlags(Qt::FramelessWindowHint);
    w.setAttribute(Qt::WA_TranslucentBackground);
    w.show();
    w.move(200,100);
    return a.exec();
}
