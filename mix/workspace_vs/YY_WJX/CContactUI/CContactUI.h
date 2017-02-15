#ifndef CCONTACTUI_H
#define CCONTACTUI_H

#include <QtGui/QMainWindow>


#include "CContactMB_GRP.h"
#include "ui_CContactUI.h"

class CContactUI : public QMainWindow
{
	Q_OBJECT

public:
	CContactUI(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CContactUI();

public slots:
	void SlotShow();

private:
	Ui::CContactUIClass ui;

	CContactMB_GRP mb;
};

#endif // CCONTACTUI_H
