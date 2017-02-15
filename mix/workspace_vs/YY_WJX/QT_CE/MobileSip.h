#ifndef QT_TEST_H
#define QT_TEST_H

#include <QtGui/QMainWindow>
#include "ui_MobileSip.h"
#include "wtypes.h"
#include "sipapi.h"
#include <QMap>
#include <QInputDialog>

class MobileSip : public QMainWindow
{
	Q_OBJECT
public:
	MobileSip(QWidget *parent = 0);
	~MobileSip();

public slots:
	void ShowSIP();
	void ShowSIP_PANEL();

private:
	Ui::MobileSipClass ui;
	QStringList m_sipList; 
};

#endif // QT_TEST_H
