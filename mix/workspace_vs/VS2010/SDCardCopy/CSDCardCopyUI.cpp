#include "CSDCardCopyUI.h"
#include <windows.h>
#include <QMessageBox>
#include <shlobj.h>
#include <Winioctl.h>
#include <QFileInfo>
#include <QFile>
#include <QDir>

void FormatMyDisk(char * m_TransData,DWORD &len,UINT &m_Command)
{
	char FormatW2KParam[100] = {0};

	sprintf(FormatW2KParam,"ECHO Y | format %c:/force/q",
		m_TransData[0]);

	system(FormatW2KParam);
}

CSDCardCopyUI::CSDCardCopyUI(QWidget *parent, Qt::WFlags flags)
: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	m_pDiskSelectUI = new CDiskSelectUI(0);
	m_pThread = new CCopyThread(this);

	ui.pushButton_OK->setEnabled(true);
	ui.pushButton_Cancel->setEnabled(false);

	connect(ui.action_Setup, SIGNAL(triggered()), this, SLOT(SlotSetup()));
	connect(ui.pushButton_OK, SIGNAL(clicked()), this, SLOT(SlotOK()));
	connect(ui.pushButton_Cancel, SIGNAL(clicked()), this, SLOT(SlotCancel()));
	connect(m_pThread, SIGNAL(SignalPassByte(qint64,const QString&, const QString&)), this, SLOT(SlotProgress(qint64,const QString&, const QString&)));

	m_pTimer = new QTimer(this);

	connect(m_pTimer, SIGNAL(timeout()), this, SLOT(SlotUpdate()));	
}

CSDCardCopyUI::~CSDCardCopyUI()
{
	delete m_pDiskSelectUI;

	if(m_pThread->isRunning())
	{
		m_pThread->terminate();
		m_pThread->wait(); 
	}

	delete m_pThread;
}

void CSDCardCopyUI::SlotSetup()
{
	m_pDiskSelectUI->InitUI();
	m_pDiskSelectUI->show();
}

void CSDCardCopyUI::SlotOK()
{
	//开始拷贝
	// 1.检查两个盘符是否有SD卡
	// 2.格式化新SD卡
	// 3.开始拷贝
	/*DWORD SHFormatDrive(HWND hwnd,
	UINT drive,//0 for A:, 2 for C:,...
	UINT fmtID,//SHFMT_ID_DEFAULT only
	UINT options//SHFMT_OPT_FULL取消快格,进行全格
	//SHFMT_OPT_SYSONLY 创建ms-dos启动盘
	);*/

	QFile file_old(m_pDiskSelectUI->GetOld() + "__test_CSDCardCopyUI__.txt");
	QFile file_new(m_pDiskSelectUI->GetNew() + "__test_CSDCardCopyUI__.txt");

	if(file_old.open(QIODevice::WriteOnly | QIODevice::Append))
	{
		file_old.close();
		QFile::remove (m_pDiskSelectUI->GetOld() + "__test_CSDCardCopyUI__.txt");
	}
	else
	{
		QMessageBox::information(this, QString::fromLocal8Bit("提示"), QString::fromLocal8Bit("原盘符无SD卡"));

		return ;
	}

	if(file_new.open(QIODevice::WriteOnly | QIODevice::Append))
	{
		file_new.close();
		QFile::remove (m_pDiskSelectUI->GetNew() + "__test_CSDCardCopyUI__.txt");
	}
	else
	{
		QMessageBox::information(this, QString::fromLocal8Bit("提示"), QString::fromLocal8Bit("新盘符无SD卡"));

		return ;
	}


	//if(QDir(m_pDiskSelectUI->GetOld()).entryInfoList().count() == 0)
	//{
	//	QMessageBox::information(this, QString::fromLocal8Bit("提示"), QString::fromLocal8Bit("原盘符无SD卡"));

	//	return ;
	//}

	//if(QDir(m_pDiskSelectUI->GetNew()).entryInfoList().count() == 0)
	//{
	//	QMessageBox::information(this, QString::fromLocal8Bit("提示"), QString::fromLocal8Bit("新盘符无SD卡"));

	//	return ;
	//}
	


	//return ;

	char chrDriver;
	DWORD len;
	UINT command;

	memcpy(&chrDriver, m_pDiskSelectUI->GetNew().toAscii().constData(), 1);
	FormatMyDisk(&chrDriver,len, command);

	//DWORD dw =  SHFormatDrive(NULL, chrDriver - 'A', SHFMT_ID_DEFAULT, 0);

	//FortFunction(chrDriver);

	//if(dw == SHFMT_ERROR)
	//{
	//	QMessageBox::information(this, QString::fromLocal8Bit("提示"), QString::fromLocal8Bit("上次格式化出错，磁盘可能被格式化"));

	//	return ;
	//}
	//else if(dw == SHFMT_CANCEL)
	//{
	//	QMessageBox::information(this, QString::fromLocal8Bit("提示"), QString::fromLocal8Bit("格式化被取消"));

	//	return ;
	//}
	//else if(dw == SHFMT_NOFORMAT)
	//{
	//	QMessageBox::information(this, QString::fromLocal8Bit("提示"), QString::fromLocal8Bit("不能进行磁盘格式化"));

	//	return ;
	//}


	m_pThread->SetFileNameOld(m_pDiskSelectUI->GetOld());
	m_pThread->SetFileNameNew(m_pDiskSelectUI->GetNew());

	ui.label->setText(QString::fromLocal8Bit("开始拷贝"));
	ui.pushButton_OK->setEnabled(false);
	ui.pushButton_Cancel->setEnabled(true);
	m_pThread->start();
	m_pTimer->start(5000);
}

void CSDCardCopyUI::SlotCancel()
{
	//取消拷贝
	if(m_pThread->isRunning())
	{
		m_pThread->terminate();    //终止线程  
		m_pThread->wait(); 
		m_pTimer->stop();
		ui.label->setText(QString::fromLocal8Bit("取消拷贝"));
		ui.pushButton_OK->setEnabled(true);
		ui.pushButton_Cancel->setEnabled(false);
	}
}

void CSDCardCopyUI::SlotProgress(qint64 value,const QString& from, const QString& to)
{
	ui.progressBar->setValue(value);
	ui.label->setText(from + QString("->") + to);
}

void CSDCardCopyUI::SlotUpdate()
{
	if(m_pThread->isFinished())
	{
		ui.label->setText(QString::fromLocal8Bit("拷贝完毕"));

		ui.pushButton_OK->setEnabled(true);
		ui.pushButton_Cancel->setEnabled(false);

		m_pTimer->stop();
	}
}

