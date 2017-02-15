#include "cchgstatus.h"
#include <QMessageBox>

CChgStatus::CChgStatus(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	connect(ui.action, SIGNAL(triggered()), this, SLOT(SlotChg()));
	connect(this, SIGNAL(Signal()), this, SLOT(Show()));
}

CChgStatus::~CChgStatus()
{

}

void CChgStatus::SlotChg()
{
	static int i = 1;
	if(i > 0)
	{
		emit Signal();
		ui.actionExit->setDisabled(true);
	}
	else
	{
		ui.actionExit->setDisabled(false);
	}
	i *= -1;
}

void CChgStatus::Show()
{
	QMessageBox::warning(this,"¾¯¸æ","show","a","b");
}
