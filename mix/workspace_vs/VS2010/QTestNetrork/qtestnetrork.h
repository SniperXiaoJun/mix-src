#ifndef QTESTNETRORK_H
#define QTESTNETRORK_H

#include <QtGui/QMainWindow>

#include <QNetworkAccessManager>
#include "ui_qtestnetrork.h"
#include <QFileInfo>
#include <Qfile>
#include <QNetworkRequest>
#include <QUrl>
#include <QTextCodec>
#include <QNetworkReply>
#include <QFileDialog>

class QTestNetrork : public QMainWindow
{
	Q_OBJECT

public:
	QTestNetrork(QWidget *parent = 0, Qt::WFlags flags = 0);
	~QTestNetrork();

	private slots:
		void replyFinished(QNetworkReply *);

		void startRequest(QUrl url); //请求链接  
private slots:      
	void on_pushButton_clicked();  //下载按钮的单击事件槽函数     
	void httpFinished();  //完成下载后的处理      
	void httpReadyRead();  //接收到数据时的处理      
	void updateDataReadProgress(qint64,qint64); //更新进度条                     


private:
	Ui::QTestNetrorkClass ui;

	QNetworkAccessManager *manager;
	QNetworkReply *reply;
	QUrl url;   //存储网络地址
	QFile *file;  //文件指针  

};

#endif // QTESTNETRORK_H
