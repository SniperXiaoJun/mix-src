#include "MobileSip.h"

QMap<QString, CLSID*> extern_map;
QMap<QString, CLSID*>::iterator extern_map_iterator;

int SipEnumIMProc(IMENUMINFO *pIMInfo)
{
	CLSID* pCLSID = new CLSID;
	memcpy(pCLSID,&pIMInfo->clsid,sizeof(CLSID));

	wchar_t * p = pIMInfo->szName;
	QString str = QString::fromUtf16((ushort *)(p));

	extern_map[str] = pCLSID;

	return 1;
}


MobileSip::MobileSip(QWidget *parent)
: QMainWindow(parent)
{
	ui.setupUi(this);

	SipEnumIM(SipEnumIMProc);

	CLSID *pCLSID = NULL;
	for(extern_map_iterator = extern_map.begin();extern_map_iterator != extern_map.end(); ++extern_map_iterator)
	{
		m_sipList.append(extern_map_iterator.key());
	}

	connect(ui.pushButton_INPUT, SIGNAL(clicked()), this, SLOT(ShowSIP()));
	connect(ui.pushButton_INPUT_PANEL, SIGNAL(clicked()), this, SLOT(ShowSIP_PANEL()));
}

MobileSip::~MobileSip()
{

}

void MobileSip::ShowSIP()
{
	QString input = QInputDialog::getItem(this, "input","select",m_sipList, 0, false);

	if(input.count() != 0)
	{
		CLSID *pCLSID = NULL;
		pCLSID = extern_map.value(input);
		SipSetCurrentIM(pCLSID);
	}
}

void MobileSip::ShowSIP_PANEL()
{
	static bool bSIP_PANEL = true;

	if(bSIP_PANEL)
	{
		//SipShowIM(SIPF_ON);
		qApp->setAutoSipEnabled(bSIP_PANEL);
		bSIP_PANEL = false;
	}
	else
	{
		//SipShowIM(SIPF_OFF);
		qApp->setAutoSipEnabled(bSIP_PANEL);
		bSIP_PANEL = true;
	}
}
