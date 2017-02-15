#include "qt_test.h"
#include <QMessageBox>

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

	connect(ui.pushButton, SIGNAL(clicked()), this, SLOT(SlotSend()));
}

QT_Test::~QT_Test()
{

}

void QT_Test::HandleReceiveData(const Byte *pMsg, u32 ulLen)
{
	//ui.textEdit->append((const char*)pMsg);
	QMessageBox::information (this, (const char*)pMsg ,(const char*)pMsg, "ok");
	int i = 0;
}

void QT_Test::HandleError(void)
{
	int j = 0;
}

void QT_Test::SlotSend()
{
	m_pNetWork->SendUDP((const Byte *)(ui.lineEdit->text().toAscii().constData()), ui.lineEdit->text().count());
	
}