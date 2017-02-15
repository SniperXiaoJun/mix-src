#include "CSetDialog.h"
#include "YY_CHAT.h"

CSetDialog::CSetDialog(YY_CHAT *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	m_pYY_CHAT = parent;

	connect(ui.pushButton_OK, SIGNAL(clicked()), this, SLOT(SlotOK()));
	connect(ui.pushButton_Cancel, SIGNAL(clicked()), this, SLOT(close()));
}

CSetDialog::~CSetDialog()
{

}

void CSetDialog::SlotOK()
{
	if(m_pYY_CHAT != NULL)
	{
		m_pYY_CHAT->SendMSG_UPDATE(ui.lineEdit_Name->text(), ui.lineEdit_Note->text());
	}
	close();
}


int CSetDialog::InitSet(QString strName, QString strNote)
{
	ui.lineEdit_Name->setText(strName);
	ui.lineEdit_Note->setText(strNote);
	return 0;
}