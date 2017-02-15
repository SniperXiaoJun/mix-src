#include "qt_test.h"


QT_Test::QT_Test(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	m_pNetWork = new CNetwork("128.1.1.121", 8888);
	m_pNetWork->SetSendAddr("127.0.0.1");
	m_pNetWork->SetSendPort(8888);
	m_pNetWork->SetCallback(this);
	m_pNetWork->ReadUDP();
	m_pNetWork->SendUDP((const Byte *)"aaa", 4);
}

QT_Test::~QT_Test()
{

}

void QT_Test::HandleReceiveData(const Byte *pMsg, u32 ulLen)
{
	int i = 0;
}

void QT_Test::HandleError(void)
{
	int j = 0;
}
