//-------------------------------------------------------------------------------------
// 文件名: CWriteMSUI.h
// 创建人: Li Qiangqiang
// 日  期: 2011-4-18
// 描  述: 类定义，定义类CWriteMSUI(编辑信息界面)
// 版  本: 1.0
//-------------------------------------------------------------------------------------
// 修改记录: 
// 修 改 人: 帅龙成
// 修改日期: 2011-06-16
// 修改目的: 加入RegisterObserver等接口
//-------------------------------------------------------------------------------------

#ifndef CWRITEMSUI_H
#define CWRITEMSUI_H

#include <QMainWindow>
#include <QCloseEvent>
#include "ui_CWriteMSUI.h"

#include "arg.h"

class CWriteMSUI : public QMainWindow
{
	Q_OBJECT

public:
	CWriteMSUI(QWidget *parent = 0);
	~CWriteMSUI();

	void NotifyObserver(CArg *pData);

	void ShowUI();
	void ShowFullScreenUI();
	void ShowMaximizedUI();
	void ShowMinimizedUI();
	void HideUI();
	void CloseUI();

	int SendSMS(QStringList stringList);
	int SendMMS(QStringList stringList);
	int SendSMS(QString numberString);
	int SendMMS(QString numberString);

	void closeEvent(QCloseEvent *event);
public slots: 
	void TextChangeSlot();

	void SendAgain(QStringList stringList);
	void SendSlot();
	void AddPage();
	void DelPage();
	void InsertImage();
	void SaveMessage();
	void NextPage();
	void BackPage();
	void AddUser();

private:
	Ui::CWriteMSUIClass ui;

	bool isMMS;                           //::彩信标识
	bool bFlag;                           //::已发送标识

	QStringList m_IncorrectNumber;


	QList<QTextBrowser *> pageList;       //::页列表
	QTextBrowser *pmessageTextBrowser;    //::页指针
	int iAddTextEditPos;                  //::页放置位置
	int iNowPageNumber;                   //::当前页

	//CSMSAdapter *m_pSMS;

	QStringList m_ImageName;
	QStringList m_TextName;


	//CSendFailed * m_Fail;                 //::
};

#endif // CWRITEMSUI_H
