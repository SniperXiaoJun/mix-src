#ifndef CWINDOWBACK_H
#define CWINDOWBACK_H

#include <QMainWindow>
#include "ui_cwindowback.h"

class CWindowBack : public QMainWindow
{
	Q_OBJECT

public:
	CWindowBack(QWidget *parent = 0);
	~CWindowBack();

private:
	Ui::CWindowBackClass ui;

	QWidget * m_pWidget;
};

#endif // CWINDOWBACK_H
