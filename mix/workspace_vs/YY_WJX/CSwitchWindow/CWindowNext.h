#ifndef CWINDOWNEXT_H
#define CWINDOWNEXT_H

#include <QMainWindow>
#include "ui_cwindownext.h"

class CWindowNext : public QMainWindow
{
	Q_OBJECT

public:
	CWindowNext(QWidget *parent = 0);
	~CWindowNext();

private:
	Ui::CWindowNextClass ui;

	QWidget * m_pWidget;
};

#endif // CWINDOWNEXT_H
