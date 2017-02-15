#ifndef CCHGSTATUS_H
#define CCHGSTATUS_H

#include <QtGui/QMainWindow>
#include "ui_cchgstatus.h"

class CChgStatus : public QMainWindow
{
	Q_OBJECT

public:
	CChgStatus(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CChgStatus();
public slots:
	void SlotChg();
	void Show();
signals:
	void Signal();

private:
	Ui::CChgStatusClass ui;
};

#endif // CCHGSTATUS_H
