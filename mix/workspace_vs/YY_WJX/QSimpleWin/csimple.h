#ifndef CSIMPLE_H
#define CSIMPLE_H

#include <QtGui/QMainWindow>
#include <QMessageBox>
#include "ui_csimple.h"

class CSimple : public QMainWindow
{
	Q_OBJECT

public:
	CSimple(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CSimple();


public slots:
	void SlotMM1();
	void SlotMM2();
	void SlotVisible();
	void FocusChangedSlot( QWidget *, QWidget *);

private:
	Ui::CSimpleClass ui;
};

#endif // CSIMPLE_H
