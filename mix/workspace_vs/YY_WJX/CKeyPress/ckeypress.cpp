#include "ckeypress.h"

CKeyPress::CKeyPress(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	this->setFocusPolicy(Qt::StrongFocus);
}

CKeyPress::~CKeyPress()
{

}

void CKeyPress::keyPressEvent ( QKeyEvent * event )
{
	if(event->key() == Qt::Key_Up)
	{
		this->close();
	}
}