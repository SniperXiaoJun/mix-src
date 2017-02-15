#include "CSwitchWindow.h"

CSwitchWindow::CSwitchWindow(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	m_iIndex = 0;
	m_pNext = NULL;
	m_pBack = NULL;

	ui.setupUi(this);
}

CSwitchWindow::~CSwitchWindow()
{
	if(NULL != m_pNext)
	{
		delete m_pNext;
	}
	if(NULL != m_pBack)
	{
		delete m_pBack;
	}
}


void CSwitchWindow::SwitchSlot()
{
	if(m_iIndex == 0)
	{
		m_pBack = new CWindowBack(this);
		m_pBack->showFullScreen();
		m_pNext->hide();
		delete m_pNext;
		m_pNext = NULL;
	}
	else
	{
		m_pNext = new CWindowNext(this);
		m_pNext->showFullScreen();
		m_pBack->hide();
		delete m_pBack;
		m_pBack = NULL;
	}
	m_iIndex++;
	m_iIndex %=2;
}

void CSwitchWindow::StartSwitch()
{
	m_pNext = new CWindowNext(this);
	m_pBack = NULL;

	m_pNext->showFullScreen();
}
