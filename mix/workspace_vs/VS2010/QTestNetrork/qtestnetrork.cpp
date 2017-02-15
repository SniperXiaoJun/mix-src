#include "qtestnetrork.h"
#include "qdebug.h"

QTestNetrork::QTestNetrork(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);
	manager = new QNetworkAccessManager(this);  //�½�QNetworkAccessManager���� 
	ui.progressBar->hide();

	//connect(manager,SIGNAL(finished(QNetworkReply*)),  //�����źźͲ�             
	//	this,SLOT(replyFinished(QNetworkReply*))); 
	//manager->get(QNetworkRequest(QUrl("http://www.yafeilinux.com"))); //��������
}

QTestNetrork::~QTestNetrork()
{

}


void QTestNetrork::replyFinished(QNetworkReply *reply)  //���ظ�������  
{      
	QTextCodec *codec = QTextCodec::codecForName("utf8");      //ʹ��utf8���룬�����ſ�����ʾ����      
	QString all = codec->toUnicode(reply->readAll());      
	ui.textEdit->setText(all);      
	reply->deleteLater();   //���Ҫ�ͷ�reply����  
} 


void QTestNetrork::startRequest(QUrl url)  //��������  
{
	reply = manager->get(QNetworkRequest(url));      //��������źźͲ�      
	connect(reply,SIGNAL(finished()),this,SLOT(httpFinished()));      //������ɺ�     
	connect(reply,SIGNAL(readyRead()),this,SLOT(httpReadyRead()));      //�п�������ʱ     
	connect(reply,SIGNAL(downloadProgress(qint64,qint64)), this,SLOT(updateDataReadProgress(qint64,qint64)));      //���½�����  
} 

void QTestNetrork::httpReadyRead()   //�п������� 
{      
	if (file)
	{
		file->write(reply->readAll());  //����ļ����ڣ���д���ļ� 
	}
} 

void QTestNetrork::updateDataReadProgress(qint64 bytesRead, qint64 totalBytes)   
{      
	ui.progressBar->setMaximum(totalBytes); //���ֵ      
	ui.progressBar->setValue(bytesRead);  //��ǰֵ  
}

void QTestNetrork::httpFinished()  //�������  
{     
	ui.progressBar->hide();      
	file->flush();      
	file->close();      
	reply->deleteLater();      
	reply = 0;      
	delete file;      
	file = 0;  
} 


void QTestNetrork::on_pushButton_clicked()  //���ذ�ť  
{      
	url = ui.lineEdit->text();   //��ȡ�ڽ����������url��ַ���磺 http://zz.onlinedown.net/down/laolafangkuaijin.rar      
	QFileInfo info(url.path());      
	QString fileName(info.fileName());      //��ȡ�ļ���     
	if (fileName.isEmpty()) fileName = "index.html";  //����ļ���Ϊ�գ���ʹ�á�index.html����  //����ʹ�á�http://www.yafeilinux.com��ʱ���ļ�����Ϊ��     
	file = new QFile(QFileDialog::getSaveFileName(this, tr("Save File"), fileName));     
	if(!file->open(QIODevice::WriteOnly))     
	{  
		//������ļ�ʧ�ܣ���ɾ��file����ʹfileָ��Ϊ0��Ȼ�󷵻�          
		qDebug() << "file open error";         
		delete file;          file = 0;          
		return;      
	}      
	startRequest(url);  //������������      
	ui.progressBar->setValue(0);  //��������ֵ��Ϊ0      
	ui.progressBar->show();  //��ʾ������  
}