#ifndef CCONTACT_H
#define CCONTACT_H

#include <QtGui/QMainWindow>
#include "ui_CContact.h"

class CContact : public QMainWindow
{
	Q_OBJECT

public:
	CContact(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CContact();

public slots:
	void SlotFind(const QString str);

private:
	Ui::CContactClass ui;
};

#endif // CCONTACT_H
