#ifndef CRES_H
#define CRES_H

#include <QtGui/QMainWindow>
#include "ui_cres.h"

class CRes : public QMainWindow
{
	Q_OBJECT

public:
	CRes(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CRes();

private:
	Ui::CResClass ui;
};

#endif // CRES_H
