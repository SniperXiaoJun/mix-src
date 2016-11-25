#ifndef QT_UILIB_H
#define QT_UILIB_H

#include "WTF_Interface.h"

class QT_UILib
{
public:
	QT_UILib();
	~QT_UILib();

	static int ShowUI(int argc, char * argv[], SK_CERT_CONTENT * pCertContent);

private:

};

#endif // QT_UILIB_H
