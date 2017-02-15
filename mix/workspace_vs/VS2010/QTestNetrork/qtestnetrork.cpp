#include "qtestnetrork.h"
#include "qdebug.h"

QTestNetrork::QTestNetrork(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);
	manager = new QNetworkAccessManager(this);  //新建QNetworkAccessManager对象 
	ui.progressBar->hide();

	//connect(manager,SIGNAL(finished(QNetworkReply*)),  //关联信号和槽             
	//	this,SLOT(replyFinished(QNetworkReply*))); 
	//manager->get(QNetworkRequest(QUrl("http://www.yafeilinux.com"))); //发送请求
}

QTestNetrork::~QTestNetrork()
{

}


void QTestNetrork::replyFinished(QNetworkReply *reply)  //当回复结束后  
{      
	QTextCodec *codec = QTextCodec::codecForName("utf8");      //使用utf8编码，这样才可以显示中文      
	QString all = codec->toUnicode(reply->readAll());      
	ui.textEdit->setText(all);      
	reply->deleteLater();   //最后要释放reply对象  
} 


void QTestNetrork::startRequest(QUrl url)  //链接请求  
{
	reply = manager->get(QNetworkRequest(url));      //下面关联信号和槽      
	connect(reply,SIGNAL(finished()),this,SLOT(httpFinished()));      //下载完成后     
	connect(reply,SIGNAL(readyRead()),this,SLOT(httpReadyRead()));      //有可用数据时     
	connect(reply,SIGNAL(downloadProgress(qint64,qint64)), this,SLOT(updateDataReadProgress(qint64,qint64)));      //更新进度条  
} 

void QTestNetrork::httpReadyRead()   //有可用数据 
{      
	if (file)
	{
		file->write(reply->readAll());  //如果文件存在，则写入文件 
	}
} 

void QTestNetrork::updateDataReadProgress(qint64 bytesRead, qint64 totalBytes)   
{      
	ui.progressBar->setMaximum(totalBytes); //最大值      
	ui.progressBar->setValue(bytesRead);  //当前值  
}

void QTestNetrork::httpFinished()  //完成下载  
{     
	ui.progressBar->hide();      
	file->flush();      
	file->close();      
	reply->deleteLater();      
	reply = 0;      
	delete file;      
	file = 0;  
} 


void QTestNetrork::on_pushButton_clicked()  //下载按钮  
{      
	url = ui.lineEdit->text();   //获取在界面中输入的url地址，如： http://zz.onlinedown.net/down/laolafangkuaijin.rar      
	QFileInfo info(url.path());      
	QString fileName(info.fileName());      //获取文件名     
	if (fileName.isEmpty()) fileName = "index.html";  //如果文件名为空，则使用“index.html”，  //例如使用“http://www.yafeilinux.com”时，文件名就为空     
	file = new QFile(QFileDialog::getSaveFileName(this, tr("Save File"), fileName));     
	if(!file->open(QIODevice::WriteOnly))     
	{  
		//如果打开文件失败，则删除file，并使file指针为0，然后返回          
		qDebug() << "file open error";         
		delete file;          file = 0;          
		return;      
	}      
	startRequest(url);  //进行链接请求      
	ui.progressBar->setValue(0);  //进度条的值设为0      
	ui.progressBar->show();  //显示进度条  
}