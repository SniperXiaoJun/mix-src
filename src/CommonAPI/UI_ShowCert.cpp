

#if 0

unsigned int __stdcall UI_ShowCert(SK_CERT_CONTENT * pCertContent)
{
	unsigned int ulRet = 0;

	CCertUIDlg dlg;

	dlg.SetCertContent(pCertContent);

	ulRet = dlg.DoModal();

	return ulRet;
}

#else 
#include "qt_uilib.h"

unsigned int __stdcall UI_ShowCert(SK_CERT_CONTENT * pCertContent)
{
	unsigned int ulRet = 0;

	int argc = 0;
	char **argv = NULL;

	QT_UILib lib;

	lib.ShowUI(argc, argv,pCertContent);

	return ulRet;
}
#endif

