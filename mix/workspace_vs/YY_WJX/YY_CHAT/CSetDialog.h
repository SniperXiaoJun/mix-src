#ifndef CSETDIALOG_H
#define CSETDIALOG_H

#include <QMainWindow>
#include "ui_CSetDialog.h"

class YY_CHAT;

class CSetDialog : public QMainWindow
{
	Q_OBJECT

public:
	CSetDialog(YY_CHAT *parent = 0);
	~CSetDialog();

	int InitSet(QString strName, QString strNote);

public slots:
	void SlotOK();

private:
	Ui::CSetDialogClass ui;
	YY_CHAT * m_pYY_CHAT;
};

#endif // CSETDIALOG_H
