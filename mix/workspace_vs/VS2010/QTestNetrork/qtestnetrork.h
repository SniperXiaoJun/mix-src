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

		void startRequest(QUrl url); //��������  
private slots:      
	void on_pushButton_clicked();  //���ذ�ť�ĵ����¼��ۺ���     
	void httpFinished();  //������غ�Ĵ���      
	void httpReadyRead();  //���յ�����ʱ�Ĵ���      
	void updateDataReadProgress(qint64,qint64); //���½�����                     


private:
	Ui::QTestNetrorkClass ui;

	QNetworkAccessManager *manager;
	QNetworkReply *reply;
	QUrl url;   //�洢�����ַ
	QFile *file;  //�ļ�ָ��  

};

#endif // QTESTNETRORK_H
