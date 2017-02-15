#include <QtGui/QApplication>
#include "mainwindow.h"
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QDir>
#include <QTime>

struct _SRecvMS_Info_Content
{
    unsigned int content_current_type;         //0 主题，1 text/plain, 2 image/gif, 3 application/smil,
    unsigned int content_current_name_length;  //
    unsigned int content_current_length;
}SRecvMS_Info_Content;

struct _SRecvMS_Info
{
    unsigned int ms_type:8;                 //信息类型 0 sms 1 mms
    unsigned int phone_number_length:8;     // 手机号码长度
    unsigned int recv_date_timer_length:8;  // 接收信息时间
    unsigned int content_count:8;
}SRecvMS_Info;

bool TraverseGetLastFile(QString & filename, QDateTime & time)
{
    if(QFileInfo(filename).isDir())
    {
        QDir dir(filename);

        QString tempFilename = filename;
        QDateTime tempTime = time;

        QList<QFileInfo> list = dir.entryInfoList();

        for(int i = 0; i < list.count(); i++)
        {
            QString str = list.at(i).fileName();
            if(str == "." || str == "..")
            {
                continue ;
            }

            tempFilename = list.at(i).absoluteFilePath();
            TraverseGetLastFile(tempFilename, tempTime);

            if(tempTime > time)
            {
                filename = tempFilename;
                time = tempTime;
            }
        }
    }
    else
    {
        if(QFileInfo(filename).created() > time)
        {
            time = QFileInfo(filename).created();
        }
    }

}



int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QTime b(23,49,44);

    QTime aa(0,0,0);




    int va = b.msecsTo(aa);

    QTime c =  QTime(0,0,0).addMSecs(va);

     qDebug(c.toString().toAscii());


//    qDebug("%d", sizeof(SRecvMS_Info));
//    qDebug("%d", sizeof(SRecvMS_Info_Content));

    QString str("N:/");
    QDateTime time;
    TraverseGetLastFile(str, time);

    qDebug(time.toString().toLocal8Bit());




    MainWindow w;
    w.show();
    
    return a.exec();
}
