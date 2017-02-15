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
	//��ʼ����
	// 1.��������̷��Ƿ���SD��
	// 2.��ʽ����SD��
	// 3.��ʼ����
	/*DWORD SHFormatDrive(HWND hwnd,
	UINT drive,//0 for A:, 2 for C:,...
	UINT fmtID,//SHFMT_ID_DEFAULT only
	UINT options//SHFMT_OPT_FULLȡ�����,����ȫ��
	//SHFMT_OPT_SYSONLY ����ms-dos������
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
		QMessageBox::information(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("ԭ�̷���SD��"));

		return ;
	}

	if(file_new.open(QIODevice::WriteOnly | QIODevice::Append))
	{
		file_new.close();
		QFile::remove (m_pDiskSelectUI->GetNew() + "__test_CSDCardCopyUI__.txt");
	}
	else
	{
		QMessageBox::information(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("���̷���SD��"));

		return ;
	}


	//if(QDir(m_pDiskSelectUI->GetOld()).entryInfoList().count() == 0)
	//{
	//	QMessageBox::information(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("ԭ�̷���SD��"));

	//	return ;
	//}

	//if(QDir(m_pDiskSelectUI->GetNew()).entryInfoList().count() == 0)
	//{
	//	QMessageBox::information(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("���̷���SD��"));

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
	//	QMessageBox::information(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("�ϴθ�ʽ���������̿��ܱ���ʽ��"));

	//	return ;
	//}
	//else if(dw == SHFMT_CANCEL)
	//{
	//	QMessageBox::information(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("��ʽ����ȡ��"));

	//	return ;
	//}
	//else if(dw == SHFMT_NOFORMAT)
	//{
	//	QMessageBox::information(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("���ܽ��д��̸�ʽ��"));

	//	return ;
	//}


	m_pThread->SetFileNameOld(m_pDiskSelectUI->GetOld());
	m_pThread->SetFileNameNew(m_pDiskSelectUI->GetNew());

	ui.label->setText(QString::fromLocal8Bit("��ʼ����"));
	ui.pushButton_OK->setEnabled(false);
	ui.pushButton_Cancel->setEnabled(true);
	m_pThread->start();
	m_pTimer->start(5000);
}

void CSDCardCopyUI::SlotCancel()
{
	//ȡ������
	if(m_pThread->isRunning())
	{
		m_pThread->terminate();    //��ֹ�߳�  
		m_pThread->wait(); 
		m_pTimer->stop();
		ui.label->setText(QString::fromLocal8Bit("ȡ������"));
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
		ui.label->setText(QString::fromLocal8Bit("�������"));

		ui.pushButton_OK->setEnabled(true);
		ui.pushButton_Cancel->setEnabled(false);

		m_pTimer->stop();
	}
}

