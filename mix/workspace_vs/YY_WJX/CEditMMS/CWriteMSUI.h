//-------------------------------------------------------------------------------------
// �ļ���: CWriteMSUI.h
// ������: Li Qiangqiang
// ��  ��: 2011-4-18
// ��  ��: �ඨ�壬������CWriteMSUI(�༭��Ϣ����)
// ��  ��: 1.0
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: ˧����
// �޸�����: 2011-06-16
// �޸�Ŀ��: ����RegisterObserver�Ƚӿ�
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

	bool isMMS;                           //::���ű�ʶ
	bool bFlag;                           //::�ѷ��ͱ�ʶ

	QStringList m_IncorrectNumber;


	QList<QTextBrowser *> pageList;       //::ҳ�б�
	QTextBrowser *pmessageTextBrowser;    //::ҳָ��
	int iAddTextEditPos;                  //::ҳ����λ��
	int iNowPageNumber;                   //::��ǰҳ

	//CSMSAdapter *m_pSMS;

	QStringList m_ImageName;
	QStringList m_TextName;


	//CSendFailed * m_Fail;                 //::
};

#endif // CWRITEMSUI_H
