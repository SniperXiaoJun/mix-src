#ifndef CKEYPRESS_H
#define CKEYPRESS_H

#include <QtGui/QMainWindow>
#include <QKeyEvent>
#include "ui_ckeypress.h"

class CKeyPress : public QMainWindow
{
	Q_OBJECT

public:
	CKeyPress(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CKeyPress();

protected:
	void keyPressEvent ( QKeyEvent * event );

private:
	Ui::CKeyPressClass ui;
};

#endif // CKEYPRESS_H
