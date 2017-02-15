#include "csimple.h"
#include "aygshell.h"
#include <winbase.h>

CSimple::CSimple(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	state = false;

	QObject::connect(ui.actionMm1,SIGNAL(triggered()),this,SLOT(SlotMM1()));
	QObject::connect(ui.actionMm2,SIGNAL(triggered()),this,SLOT(SlotMM2()));
	QObject::connect(ui.actionVisible,SIGNAL(triggered()),this,SLOT(SlotVisible()));

	QObject::connect(this,SIGNAL(SignalShowFullS()),this,SLOT(showFullScreen()));
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

bool CSimple::event(QEvent * e) 
{ 
    QEvent::Type type = e->type (); 
 
    // Somehow the correct state of window is not getting set, 
    // so doing it manually 
    if( e->type() == QEvent::Hide) 
    { 
		this->setWindowState(Qt::WindowMinimized);
		state = true;
    } 
    else if(e->type() == QEvent::Show) 
    { 
		this->setWindowState((this->windowState() & ~Qt::WindowMinimized) | 
			Qt::WindowActive);
    }
	else if(e->type() == QEvent::WindowStateChange)
	{
		if(state)
		{
			state = false;
			emit SignalShowFullS();
		}
	}
	return QMainWindow::event(e);
} 
