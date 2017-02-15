#ifndef SDCARDCOPY_H
#define SDCARDCOPY_H

#include <QTimer>

#include <QtGui/QMainWindow>
#include "CDiskSelectUI.h"
#include "CCopyThread.h"
#include "ui_CSDCardCopyUI.h"

class CSDCardCopyUI: public QMainWindow
{
	Q_OBJECT

public:
	CSDCardCopyUI(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CSDCardCopyUI();

	public slots:
		void SlotSetup();
		void SlotOK();
		void SlotCancel();
		void SlotProgress(qint64,const QString&, const QString&);
		void SlotUpdate();

private:
	Ui::CSDCardCopyUIClass ui;
	CDiskSelectUI * m_pDiskSelectUI;
	CCopyThread * m_pThread;
	QTimer * m_pTimer;
};

#endif // SDCARDCOPY_H
