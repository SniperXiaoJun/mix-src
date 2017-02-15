#ifndef CCHATDIALOG_H
#define CCHATDIALOG_H

#include <QMainWindow>
#include <QFontDialog>
#include <QFileDialog>
#include <QColorDialog>
#include <QTime>
#include <QDate>
#include <QTextBrowser>

#include "YY_CHAT_ThreadClient.h"
#include "YY_CHAT_ThreadServer.h"

class YY_CHAT;

#include "ui_CChatDialog.h"

#include "comm.h"

class CChatDialog : public QMainWindow
{
	Q_OBJECT

public:
	CChatDialog(YY_CHAT *parent = 0, SYY_CHAT_USR * usr = NULL, SYY_CHAT_USR * usrSelf = NULL);
	~CChatDialog();

	int ReceiveMSG_ReceiveMSG(QString strIP = QString(), QString strMSG = QString());

	int CommitChatLogToDB();
	QString ReadChatLogFromDB();

public slots:
	void SlotSend();
	void SlotCancel();
	void SlotFont();
	void SlotFile();
	void SlotLog();
	void SlotImg();
	void SlotColor();
	bool event(QEvent * event);

private:
	Ui::CChatDialogClass ui;
	YY_CHAT * m_pYY_CHAT;
	SYY_CHAT_USR m_USR;
	SYY_CHAT_USR m_USRSelf;
	QTextBrowser * m_pTextBrowserChatLog;
	QTreeWidgetItem * m_pTreeWidgetItem_FILE;
	YY_CHAT_ThreadServer * m_pServer;
	YY_CHAT_ThreadClient * m_pClient;
};

#endif // CCHATDIALOG_H
