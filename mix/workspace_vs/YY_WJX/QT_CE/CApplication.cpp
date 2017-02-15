#include "CApplication.h"

CApplication::CApplication(int argc, char * argv[])
	: QApplication(argc,argv)
{

}

CApplication::~CApplication()
{

}

bool CApplication::eventFilter(QObject * watched, QEvent * event)
{
	QString str = this->inputContext()->language();
	return false;
}

bool CApplication::event(QEvent * e)
{
	int type = e->type();
	switch(type)
	{
	case QEvent::ApplicationDeactivate:
		break;
	case QEvent::ApplicationActivate:
		break;
	default:
		break;
	}
	return false;
}

