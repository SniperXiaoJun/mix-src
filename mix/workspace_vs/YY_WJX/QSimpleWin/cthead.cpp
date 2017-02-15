#include "cthead.h"

CThead::CThead(QObject *parent)
	: QThead(parent)
{
	iSpaceMSecond = 10000;
}

CThead::~CThead()
{

}

void CThead::run()
{
	while(true)
	{
		this->msleep(iSpaceMSecond);
		emit SignalShow();
	}
}