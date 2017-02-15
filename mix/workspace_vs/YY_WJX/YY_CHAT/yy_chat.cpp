#include "yy_chat.h"


YY_CHAT::YY_CHAT(QWidget *parent, Qt::WFlags flags)
: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	InitYY_Chat();
}

YY_CHAT::~YY_CHAT()
{
	int k = 0;
	SYY_CHAT_USR usrTmp;

	SendMSG_LOGOUT();
	for(; k < m_listUsr.count(); k++)
	{
		m_pTreeWidgetItem = m_listUsr.at(k).pTreeWidgetItem;
		delete m_pTreeWidgetItem;
		m_pTreeWidgetItem = NULL;

		m_pChatDialog = m_listUsr.at(k).pChatDialog;
		delete m_pChatDialog;
		m_pChatDialog = NULL;
	}
	m_listUsr.clear();
	delete m_pUdpSocket;
	m_pUdpSocket = NULL;
	delete m_pSetDialog;
	m_pSetDialog = NULL;
}

int YY_CHAT::InitYY_Chat()
{
	InitYY_CHAT_USR_Self();
	InitUI();
	InitSocket();
	SendMSG_LOGIN();
	return 0;
}

int YY_CHAT::InitSocket()
{
	m_pUdpSocket = new QUdpSocket(this);
	m_pUdpSocket->bind(QHostAddress::Null, 8888, QUdpSocket::ShareAddress);

	connect(m_pUdpSocket, SIGNAL(readyRead()),
		this, SLOT(ReadPendingDatagrams()));

	return 0;
}

int YY_CHAT::InitUI()
{
	m_pSetDialog = NULL;
	ui.lineEdit_Note->setText(m_sYY_CHAT_USR_Self.strNote);
	connect(ui.treeWidget_Chat, SIGNAL(itemActivated(QTreeWidgetItem *, int)),this, SLOT(SlotTreeWidget_ChatActive(QTreeWidgetItem *, int))); 
	connect(ui.treeWidget_ChatGroup, SIGNAL(itemActivated(QTreeWidgetItem *, int)),this, SLOT(SlotTreeWidget_ChatGroupActive(QTreeWidgetItem *, int))); 
	connect(ui.pushButton_SetCenter, SIGNAL(clicked()),this, SLOT(SlotSetCenter())); 
	connect(ui.lineEdit_Note, SIGNAL(editingFinished()),this, SLOT(SlotUpdateNote())); 
	return 0;
}

int YY_CHAT::InitYY_CHAT_USR_Self()
{
	/*
	建立连接
	*/
	{
		QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
		db.setDatabaseName("YY_WJX.db");
		db.open();
	}
	/*
	创建数据库表格YY_CHAT_USR
	*/
	{
		QSqlQuery query;
		query.prepare("create table YY_CHAT_USR(name text,note text);");
		query.exec();
	}
	/*
	创建数据库表格YY_CHAT_LOG
	*/
	{
		QSqlQuery query;
		query.prepare("create table YY_CHAT_LOG(ip text,note text);");
		query.exec();
	}
	/*
	查询数据库表格
	*/
	{
		bool ok = false;
		QSqlQuery query;
		query.prepare("SELECT * FROM YY_CHAT_USR");
		query.exec();

		while(query.next())
		{
			m_sYY_CHAT_USR_Self.strName = query.value(0).toString();
			m_sYY_CHAT_USR_Self.strNote = query.value(1).toString();
			ok = true;
			break;
		}

		if(!ok)
		{
			m_sYY_CHAT_USR_Self.strName = "YY";
			m_sYY_CHAT_USR_Self.strNote = "YY无极限";
		}
	}

	return 0;
}

void YY_CHAT::ReadPendingDatagrams()
{
	while (m_pUdpSocket->hasPendingDatagrams()) {
		QByteArray datagram;
		datagram.resize(m_pUdpSocket->pendingDatagramSize());
		QHostAddress sender;
		quint16 senderPort;

		m_pUdpSocket->readDatagram(datagram.data(), datagram.size(),
			&sender, &senderPort);

		ProcessTheDatagram(sender, senderPort, datagram);
	}
}

int YY_CHAT::ProcessTheDatagram(QHostAddress sender, quint16 port,QByteArray byteArray)
{
	CGeneralMsgClass msgRecv((Byte *)byteArray.constData(),byteArray.count());

	msgRecv.ParseMsg();

	for(int i = 0; i < EFIELD_NAME_USR_COUNT; i++)
	{
		for(int j = 0; j < msgRecv.GetFieldNumber(i); j++)
		{
			switch(i)
			{
			case USR_LOGIN:
				{
					bool bOnLine = false;
					int k = 0;
					SYY_CHAT_USR usrTmp;
					for(; k < m_listUsr.count(); k++)
					{
						if(m_listUsr.at(k).strIP == sender.toString())
						{
							bOnLine = true;
							break;
						}
						else
						{
							continue;
						}
					}
					if(!bOnLine)
					{
						CUAPField field = msgRecv.GetField(i,j);

						m_pTreeWidgetItem = new QTreeWidgetItem(ui.treeWidget_Chat);
						m_pTreeWidgetItem->setText(0, sender.toString());

						usrTmp.pChatDialog = NULL;
						usrTmp.pTreeWidgetItem = m_pTreeWidgetItem;
						usrTmp.strIP = sender.toString();

						m_listUsr.append(usrTmp);
						SendMSG_LOGIN();
					}
				}
				break;
			case USR_LOGOUT:
				{
					bool bOnLine = false;
					int k = 0;
					SYY_CHAT_USR usrTmp;
					for(; k < m_listUsr.count(); k++)
					{
						if(m_listUsr.at(k).strIP == sender.toString())
						{
							bOnLine = true;
							break;
						}
						else
						{
							continue;
						}
					}
					if(bOnLine)
					{
						CUAPField field = msgRecv.GetField(i,j);

						m_pTreeWidgetItem = m_listUsr.at(k).pTreeWidgetItem;
						delete m_pTreeWidgetItem;
						m_pTreeWidgetItem = NULL;

						m_pChatDialog = m_listUsr.at(k).pChatDialog;
						delete m_pChatDialog;
						m_pChatDialog = NULL;

						m_listUsr.removeAt(k);

					}
				}
				break;
			case USR_MSG:
				{
					bool bOnLine = false;
					int k = 0;
					SYY_CHAT_USR usrTmp;
					for(; k < m_listUsr.count(); k++)
					{
						if(m_listUsr.at(k).strIP == sender.toString())
						{
							bOnLine = true;
							break;
						}
						else
						{
							continue;
						}
					}
					if(bOnLine)
					{
						CUAPField field = msgRecv.GetField(i,j);

						QString strMSG = QString(QByteArray((char *)(field.GetValue()), field.GetLength()));
						if(m_listUsr.at(k).pChatDialog == NULL)
						{
							usrTmp = m_listUsr.at(k);

							m_pChatDialog = new CChatDialog(this, &usrTmp);
							m_pChatDialog->show();

							usrTmp.pChatDialog = m_pChatDialog;

							m_listUsr.removeAt(k);
							m_listUsr.append(usrTmp);
						}
						else
						{
							m_listUsr.at(k).pChatDialog->show();
						}
						m_listUsr.at(k).pChatDialog->ReceiveMSG_ReceiveMSG(sender.toString(),strMSG);
					}
				}
				break;
			case USR_NAME:
				{
					bool bOnLine = false;
					int k = 0;
					SYY_CHAT_USR usrTmp;
					for(; k < m_listUsr.count(); k++)
					{
						if(m_listUsr.at(k).strIP == sender.toString())
						{
							bOnLine = true;
							break;
						}
						else
						{
							continue;
						}
					}
					if(bOnLine)
					{
						CUAPField field = msgRecv.GetField(i,j);

						m_pTreeWidgetItem = m_listUsr.at(k).pTreeWidgetItem;
						m_pTreeWidgetItem->setText(1, QString(QByteArray((char *)(field.GetValue()), field.GetLength())));

						usrTmp = m_listUsr.at(k);
						usrTmp.strName = QString(QByteArray((char *)(field.GetValue()), field.GetLength()));

						m_listUsr.removeAt(k);
						m_listUsr.append(usrTmp);
					}
				}
				break;
			case USR_COMMENT:
				{
					bool bOnLine = false;
					int k = 0;
					SYY_CHAT_USR usrTmp;
					for(; k < m_listUsr.count(); k++)
					{
						if(m_listUsr.at(k).strIP == sender.toString())
						{
							bOnLine = true;
							break;
						}
						else
						{
							continue;
						}
					}
					if(bOnLine)
					{
						CUAPField field = msgRecv.GetField(i,j);

						m_pTreeWidgetItem = m_listUsr.at(k).pTreeWidgetItem;
						m_pTreeWidgetItem->setText(2, QString(QByteArray((char *)(field.GetValue()), field.GetLength())));

						usrTmp = m_listUsr.at(k);
						usrTmp.strNote = QString(QByteArray((char *)(field.GetValue()), field.GetLength()));

						m_listUsr.removeAt(k);
						m_listUsr.append(usrTmp);
					}
				}
				break;
			default:
				break;
			}
		}
	}
	return 0;
}

int YY_CHAT::SendMSG_LOGIN(QString strIP, QString strMSG)
{
	CGeneralMsgClass msgLogin;

	CUAPField fieldLogin(USR_LOGIN);
	fieldLogin.SetValue((UInt32)USR_LOGIN);
	msgLogin.AddField(fieldLogin);

	CUAPField fieldName(USR_NAME);
	fieldName.SetValue(m_sYY_CHAT_USR_Self.strName.toAscii().data());
	msgLogin.AddField(fieldName);

	CUAPField fieldComment(USR_COMMENT);
	fieldComment.SetValue(m_sYY_CHAT_USR_Self.strNote.toAscii().data());
	msgLogin.AddField(fieldComment);

	msgLogin.PackMsg();

	int length = msgLogin.GetLength();
	QByteArray byteLogin = QByteArray((char *)(msgLogin.GetValue()), msgLogin.GetLength());

	m_pUdpSocket->writeDatagram(byteLogin, QHostAddress::Broadcast, 8888);

	return 0;
}

int YY_CHAT::SendMSG_UPDATE(QString strName, QString strNote)
{
	m_sYY_CHAT_USR_Self.strName = strName;
	m_sYY_CHAT_USR_Self.strNote =strNote;

	ui.lineEdit_Note->setText(strNote);

	/*
	查询数据库表格
	*/
	{
		bool ok = false;
		QSqlQuery query;
		query.prepare("SELECT * FROM YY_CHAT_USR");

		query.exec();

		while(query.next())
		{
			ok = true;
			break;
		}

		if(ok)
		{
			QSqlQuery query;
			QString queryString = "update YY_CHAT_USR";

			queryString += " set ";
			queryString += "name=";
			queryString += "\"";
			queryString += strName;
			queryString += "\"";

			queryString += ",note=";
			queryString += "\"";
			queryString += strNote;
			queryString += "\"";

			query.prepare(queryString);
			query.exec();
		}
		else
		{
			QSqlQuery query;

			query.prepare("INSERT INTO YY_CHAT_USR(name, note)"
				"VALUES (:name, :note)");

			query.bindValue(":name", strName);
			query.bindValue(":note", strNote);

			query.exec();
		}
	}

	SendMSG_LOGOUT();
	SendMSG_LOGIN();

	return 0;
}


int YY_CHAT::SendMSG_LOGOUT(QString strIP, QString strMSG)
{
	CGeneralMsgClass msgLogOut;

	CUAPField fieldLogOut(USR_LOGOUT);
	fieldLogOut.SetValue((UInt32)USR_LOGOUT);
	msgLogOut.AddField(fieldLogOut);

	msgLogOut.PackMsg();

	QByteArray byteLogOut = QByteArray((char *)(msgLogOut.GetValue()), msgLogOut.GetLength());

	m_pUdpSocket->writeDatagram(byteLogOut, QHostAddress::Broadcast, 8888);

	return 0;
}

int YY_CHAT::SendMSG_SendMSG(QString strIP, QString strMSG)
{
	CGeneralMsgClass msgMSG;

	CUAPField fieldMSG(USR_MSG);
	fieldMSG.SetValue(strMSG.toAscii().data());
	msgMSG.AddField(fieldMSG);

	msgMSG.PackMsg();

	QByteArray byteMSG = QByteArray((char *)(msgMSG.GetValue()), msgMSG.GetLength());

	m_pUdpSocket->writeDatagram(byteMSG, QHostAddress(strIP), 8888);

	return 0;
}

void YY_CHAT::SlotTreeWidget_ChatActive( QTreeWidgetItem * item, int column)
{
	int k = 0;
	SYY_CHAT_USR usrTmp;
	for(; k < m_listUsr.count(); k++)
	{
		if(m_listUsr.at(k).pTreeWidgetItem == item)
		{
			if(m_listUsr.at(k).pChatDialog == NULL)
			{
				usrTmp = m_listUsr.at(k);

				m_pChatDialog = new CChatDialog(this, &usrTmp, &m_sYY_CHAT_USR_Self);
				m_pChatDialog->show();

				usrTmp.pChatDialog = m_pChatDialog;

				m_listUsr.removeAt(k);
				m_listUsr.append(usrTmp);
			}
			else
			{
				m_listUsr.at(k).pChatDialog->show();
			}
			break;
		}
	}
}

void YY_CHAT::SlotTreeWidget_ChatGroupActive( QTreeWidgetItem * item, int column)
{
	m_pChatDialog = new CChatDialog(this);
	m_pChatDialog->show();
}

void YY_CHAT::SlotSetCenter()
{
	if(m_pSetDialog == NULL)
	{
		m_pSetDialog = new CSetDialog(this);
		m_pSetDialog->InitSet(m_sYY_CHAT_USR_Self.strName,m_sYY_CHAT_USR_Self.strNote);
	}
	m_pSetDialog->InitSet(m_sYY_CHAT_USR_Self.strName,m_sYY_CHAT_USR_Self.strNote);
	m_pSetDialog->show();
}

void YY_CHAT::SlotUpdateNote()
{
	m_sYY_CHAT_USR_Self.strNote = ui.lineEdit_Note->text();
	
	QString strNote = m_sYY_CHAT_USR_Self.strNote;
	QString strName = m_sYY_CHAT_USR_Self.strName;
	/*
	查询数据库表格
	*/
	{
		bool ok = false;
		QSqlQuery query;
		query.prepare("SELECT * FROM YY_CHAT_USR");

		query.exec();

		while(query.next())
		{
			ok = true;
			break;
		}

		if(ok)
		{
			QSqlQuery query;
			QString queryString = "update YY_CHAT_USR";

			queryString += " set ";
			queryString += "name=";
			queryString += "\"";
			queryString += strName;
			queryString += "\"";

			queryString += ",note=";
			queryString += "\"";
			queryString += strNote;
			queryString += "\"";

			query.prepare(queryString);
			query.exec();
		}
		else
		{
			QSqlQuery query;

			query.prepare("INSERT INTO YY_CHAT_USR(name, note)"
				"VALUES (:name, :note)");

			query.bindValue(":name", strName);
			query.bindValue(":note", strNote);

			query.exec();
		}
	}

	SendMSG_LOGOUT();
	SendMSG_LOGIN();
}