#include "CWindowNext.h"

CWindowNext::CWindowNext(QWidget *parent)
	: QMainWindow(parent)
{
	m_pWidget = parent;
	ui.setupUi(this);

	QObject::connect(ui.pushButton, SIGNAL(clicked()), m_pWidget,SLOT(SwitchSlot()));
}

CWindowNext::~CWindowNext()
{

}
