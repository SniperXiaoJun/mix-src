#ifndef CBITMAPMASK_H
#define CBITMAPMASK_H

#include <QtGui/QMainWindow>
#include <QPixmap>
#include <QBitmap>
#include <QLabel>
#include "ui_CBitmapMask.h"

class CBitmapMask : public QMainWindow
{
	Q_OBJECT

public:
	CBitmapMask(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CBitmapMask();

public slots:
	void ShowBmp();

private:
	Ui::CBitmapMaskClass ui;
	QLabel * m_pLabel;
};

#endif // CBITMAPMASK_H
