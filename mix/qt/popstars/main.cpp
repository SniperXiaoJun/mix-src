#include <QApplication>
#include "mainboard.h"
#include"form.h"
#include"failedform.h"
#include"ranklistform.h"
#include<QTextCodec>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    //QTextCodec::setCodecForCStrings(QTextCodec::codecForName("GB18030"));
    QTextCodec::setCodecForLocale(QTextCodec::codecForName("GB18030"));
    //QTextCodec::setCodecForTr(QTextCodec::codecForName("GB18030"));


    mainBoard w;

    //w.showMaximized();

     w.show();

    return a.exec();
}
