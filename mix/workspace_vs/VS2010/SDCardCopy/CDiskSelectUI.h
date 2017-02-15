#ifndef CDISKSELECTUI_H
#define CDISKSELECTUI_H

#include <QWidget>
#include "ui_CDiskSelectUI.h"

class CDiskSelectUI : public QWidget
{
	Q_OBJECT

public:
	CDiskSelectUI(QWidget *parent = 0);
	~CDiskSelectUI();

	int InitUI();

	QString GetNew();
	QString GetOld();

	public slots:
		void SlotNew();
		void SlotOld();

private:
	Ui::CDiskSelectUIClass ui;
	QString m_strOld;
	QString m_strNew;
};

#endif // CDISKSELECTUI_H
