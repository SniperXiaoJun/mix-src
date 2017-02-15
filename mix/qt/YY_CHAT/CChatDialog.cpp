#include "CChatDialog.h"
#include "YY_CHAT.h"

CChatDialog::CChatDialog(YY_CHAT *parent, SYY_CHAT_USR * usr, SYY_CHAT_USR * usrSelf)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	if(usr != NULL)
	{
		m_USR = *usr;
	}
	if(usrSelf != NULL)
	{
		m_USRSelf = *usrSelf;
	}
	
	m_pTextBrowserChatLog = NULL;
	m_pYY_CHAT = parent;
	this->setWindowTitle(m_USR.strIP + m_USR.strName);

	connect(ui.pushButton_Send, SIGNAL(clicked()), this , SLOT(SlotSend()));
	connect(ui.pushButton_Cancel, SIGNAL(clicked()), this , SLOT(close()));
	connect(ui.pushButton_Log, SIGNAL(clicked()), this , SLOT(SlotLog()));
	connect(ui.pushButton_File, SIGNAL(clicked()), this , SLOT(SlotFile()));
	connect(ui.pushButton_Font, SIGNAL(clicked()), this , SLOT(SlotFont()));
	connect(ui.pushButton_Img, SIGNAL(clicked()), this , SLOT(SlotImg()));
	connect(ui.pushButton_Color, SIGNAL(clicked()), this , SLOT(SlotColor()));
}

CChatDialog::~CChatDialog()
{
	if(m_pTextBrowserChatLog != NULL)
	{
		delete m_pTextBrowserChatLog;
		m_pTextBrowserChatLog = NULL;
	}
}

void CChatDialog::SlotSend()
{
	QString strMSG = ui.textEdit_Send->toPlainText();

	QString strMSGHead;
	/*strMSGHead += "  ";*/
	strMSGHead += m_USRSelf.strName;
	strMSGHead += " ";
	strMSGHead += QDate::currentDate().toString();
	strMSGHead += " ";
	strMSGHead += QTime::currentTime().toString();

	if(0 != strMSG.count())
	{
		ui.textEdit_All->append(strMSGHead);
		ui.textEdit_All->append(strMSG);

		m_pYY_CHAT->SendMSG_SendMSG(m_USR.strIP, strMSG);

		ui.textEdit_Send->clear();
	}

    if(ui.treeWidget_FILE_SEND->topLevelItemCount() > 0)
    {
        m_pServer = new YY_CHAT_ThreadServer(NULL);
        m_pServer->SetFileName(ui.treeWidget_FILE_SEND->topLevelItem(0)->text(2));

        m_pClient = new YY_CHAT_ThreadClient(NULL);
        m_pClient->SetFileName("d:/eee.exe");
    }
}

int CChatDialog::ReceiveMSG_ReceiveMSG(QString strIP, QString strMSG)
{
	QString strMSGHead;
	/*strMSGHead += "  ";*/
	strMSGHead += m_USR.strName;
	strMSGHead += " ";
	strMSGHead += QDate::currentDate().toString();
	strMSGHead += " ";
	strMSGHead += QTime::currentTime().toString();

	ui.textEdit_All->append(strMSGHead);
	ui.textEdit_All->append(strMSG);

	return 0;
}

void CChatDialog::SlotCancel()
{

}

void CChatDialog::SlotFont()
{
	bool ok;
	QFont font = QFontDialog::getFont(&ok, QFont("Helvetica [Cronyx]", 10), this);
	if (ok) {
		ui.textEdit_All->setCurrentFont(font);
		ui.textEdit_Send->setCurrentFont(font);
	} else {
		return;
	}
}

void CChatDialog::SlotFile()
{
	QString fileName = QFileDialog::getOpenFileName(this, "", "/", "") ;

	if(fileName == QString())
	{
		return;
	}
	else
	{
		QFile file(fileName);
		m_pTreeWidgetItem_FILE = new QTreeWidgetItem(ui.treeWidget_FILE_SEND);

		m_pTreeWidgetItem_FILE->setText(0, fileName.section("/", -1));
		m_pTreeWidgetItem_FILE->setText(1, QString::number(QFileInfo(fileName).size()));
		m_pTreeWidgetItem_FILE->setText(2, fileName.section("/",0));
		m_pTreeWidgetItem_FILE->setText(3, "0%");
	}
}

void CChatDialog::SlotLog()
{
	if(m_pTextBrowserChatLog == NULL)
	{
		m_pTextBrowserChatLog = new QTextBrowser(this);
		//m_pTextBrowserChatLog->setMinimumSize(250, 250);
		ui.gridLayout_Frame->addWidget(m_pTextBrowserChatLog, 0, 1, 1, 1);
		m_pTextBrowserChatLog->setPlainText(ReadChatLogFromDB());
		m_pTextBrowserChatLog->show();
	}
	else
	{
		delete m_pTextBrowserChatLog;
		m_pTextBrowserChatLog = NULL;
	}
}

void CChatDialog::SlotImg()
{

}

void CChatDialog::SlotColor()
{
	QColor color = ui.textEdit_All->textColor();
	color = QColorDialog::getColor(color, this,"ÉèÖÃÑÕÉ«");

	ui.textEdit_All->setTextColor(color);
	ui.textEdit_Send->setTextColor(color);
}


bool CChatDialog::event(QEvent * event)
{
	int type = event->type();

	//common events
	if(type == 68 
		|| type == 33 
		|| type == 203 
		|| type == 75 
		|| type == 70
		|| type == 69 
		|| type == 153
		|| type == 13 
		|| type == 14 
		|| type == 152
		|| type == 17
		|| type == 24
		|| type == 99 
		|| type == 26 
		|| type == 67 
		|| type == 74
		|| type == 76 
		|| type == 77
		|| type == 12 
		|| type == 25 
		|| type == 10 
		|| type == 11 
		|| type == 127
		|| type == 86 
		|| type == 128 
		|| type == 129
		|| type == 110 
		|| type == 173)
	{
		return QMainWindow::event(event);
	}
    
	//QEvent::Hide
	//18
	//QEvent::HideToParent
	//27
	//QEvent::Close
	//19
	//
	//QEvent::NonClientAreaMouseButtonPress
	//174
	//A mouse button press occurred outside the client area.


	switch(type)//19, 18, 27    174
	{
	case QEvent::Close:
		CommitChatLogToDB();
		ui.textEdit_All->clear();
		ui.textEdit_Send->clear();
		break;
	default:
		break;
	}
	return QMainWindow::event(event);
}

int CChatDialog::CommitChatLogToDB()
{
	QSqlQuery query;

	query.prepare("INSERT INTO YY_CHAT_LOG(ip, note)"
		"VALUES (:ip, :note)");

	query.bindValue(":ip", m_USR.strIP);
	query.bindValue(":note", ui.textEdit_All->toPlainText());

	query.exec();

	return 0;
}

QString CChatDialog::ReadChatLogFromDB()
{
	QString strLog;
	QSqlQuery query;

	QString queryString;
	
	queryString += "SELECT * FROM YY_CHAT_LOG";
	queryString += " where ip=";
	queryString += "\"";
	queryString += m_USR.strIP;
	queryString += "\"";

	query.prepare(queryString);
	
	query.exec();

	while(query.next())
	{
		strLog += query.value(1).toString();
	}

	return strLog;
}
