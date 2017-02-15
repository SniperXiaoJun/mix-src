#ifndef YY_CHAT_H
#define YY_CHAT_H

#include <QtGui/QMainWindow>
#include <QUdpSocket>
#include <QList>
#include <QSqlDatabase>
#include <QSqlQuery>

#include "CGeneralMsgClass.h"
#include "ui_yy_chat.h"
#include "comm.h"
#include "CChatDialog.h"
#include "CSetDialog.h"

class YY_CHAT : public QMainWindow
{
	Q_OBJECT

public:
	YY_CHAT(QWidget *parent = 0, Qt::WFlags flags = 0);
	~YY_CHAT();

	int InitYY_Chat();
	int InitSocket();
	int InitUI();
	int InitYY_CHAT_USR_Self();
	int ProcessTheDatagram(QHostAddress sender, quint16 port,QByteArray byteArray);
	int SendMSG_UPDATE(QString strName  = QString(), QString strNote = QString());
	int SendMSG_LOGIN(QString strIP  = QString(), QString strMSG = QString());
	int SendMSG_LOGOUT(QString strIP  = QString(), QString strMSG = QString());
	int SendMSG_SendMSG(QString strIP = QString(), QString strMSG = QString());
	

public slots:
	
	void ReadPendingDatagrams();
	void SlotTreeWidget_ChatActive( QTreeWidgetItem * item, int column);
	void SlotTreeWidget_ChatGroupActive( QTreeWidgetItem * item, int column);
	void SlotSetCenter();
	void SlotUpdateNote();
	

private:
	QList<SYY_CHAT_USR> m_listUsr;
	Ui::YY_CHATClass ui;
	QUdpSocket * m_pUdpSocket;
	CChatDialog * m_pChatDialog;
	CSetDialog * m_pSetDialog;
	QTreeWidgetItem * m_pTreeWidgetItem;
	SYY_CHAT_USR m_sYY_CHAT_USR_Self;
};

#endif // YY_CHAT_H
