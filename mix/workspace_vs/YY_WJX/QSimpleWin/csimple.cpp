#include "csimple.h"

CSimple::CSimple(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	QObject::connect(ui.actionMm1,SIGNAL(triggered()),this,SLOT(SlotMM1()));
	QObject::connect(ui.actionMm2,SIGNAL(triggered()),this,SLOT(SlotMM2()));
	QObject::connect(ui.actionVisible,SIGNAL(triggered()),this,SLOT(SlotVisible()));
}

CSimple::~CSimple()
{

}


void CSimple::SlotMM1()
{
	QMessageBox::warning(this,QString::fromLocal8Bit("警告"),
		QString::fromLocal8Bit( "警告!"),
		QString::fromLocal8Bit("确定"));
}

void CSimple::SlotMM2()
{
	QMessageBox::information(this,QString::fromLocal8Bit("通知"),
		QString::fromLocal8Bit( "通知!"),
		QString::fromLocal8Bit("确定"));
}

void CSimple::SlotVisible()
{
	this->setVisible(false);
}

void CSimple::FocusChangedSlot( QWidget *old, QWidget *now)
{
	if(this->isActiveWindow())
	{
		return ;
	}
	else
	{
		this->showFullScreen();

	}
}