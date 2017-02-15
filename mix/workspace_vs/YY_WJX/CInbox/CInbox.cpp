
#include "CInbox.h"

CInbox::CInbox(QWidget *parent)
    : QMainWindow(parent)
{
	ui.setupUi(this);


	char ** p = new (char * [4]); 
	delete [] p;
	
	
    m_Icon.addFile(QString::fromUtf8(":/new/prefix1/picIcon/a/EAbout.bmp"), QSize(), QIcon::Normal, QIcon::Off);
    
    m_Font.setPointSize(10);

	connect(ui.pushButton, SIGNAL(clicked()), this, SLOT(SlotAddNewMsg()));
	connect(ui.listWidget, SIGNAL(itemActivated(QListWidgetItem * )), this, SLOT(SlotItemActivated(QListWidgetItem *)));

}

CInbox::~CInbox()
{

}

void CInbox::SlotAddNewMsg()
{
	AddNewMsg();
}

void CInbox::AddNewMsg(char * name, char * content)
{
	QString show = QString(name) + "\n" + QString(content);

	//show = QString::fromLocal8Bit(show.toAscii().constData());
	m_pItem = new QListWidgetItem();
    m_pItem->setFont(m_Font);
    m_pItem->setIcon(m_Icon);
	m_pItem->setText(show);
	ui.listWidget->insertItem(0,m_pItem);

}

void CInbox::SlotItemActivated(QListWidgetItem * item)
{
	delete item;
}


void CInbox::SetInformation(void *)
{
//set;
}

void CInbox::NoticeCtrl(void *)
{
//ctrl->ProcessFun();
}
