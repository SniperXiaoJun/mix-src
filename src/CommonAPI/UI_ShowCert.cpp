
#include "WTF_Interface.h"
#include "qt_uilib.h"

unsigned int __stdcall UI_ShowCert(SK_CERT_CONTENT * pCertContent)
{
	unsigned int ulRet = 0;

	QT_UILIB_ShowUI((unsigned char *)pCertContent + sizeof(SK_CERT_CONTENT), pCertContent->nValueLen);

	return ulRet;
}


