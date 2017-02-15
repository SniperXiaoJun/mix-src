#ifndef CSWITCHWINDOW_H
#define CSWITCHWINDOW_H

#include <QtGui/QMainWindow>
#include "ui_CSwitchWindow.h"
#include "CWindowNext.h"
#include "CWindowBack.h"

class CSwitchWindow : public QMainWindow
{
	Q_OBJECT

public:
	CSwitchWindow(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CSwitchWindow();
	void StartSwitch();



public slots:
	void SwitchSlot();


private:
	Ui::CSwitchWindowClass ui;

	int m_iIndex;

	CWindowNext * m_pNext;
	CWindowBack * m_pBack;
};

#endif // CSWITCHWINDOW_H
