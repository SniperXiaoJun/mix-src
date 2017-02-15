#ifndef CTEXT_H
#define CTEXT_H

#include <QtGui/QMainWindow>
#include <QFileDialog>
#include <QColorDialog>
#include "ui_ctext.h"

class CText : public QMainWindow
{
	Q_OBJECT

public:
	CText(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CText();

public slots:
	void ADD(); 
	void ADD2();

private:
	QColorDialog * cdialog;
	QFileDialog *pfDialog;
	Ui::CTextClass ui;
};

#endif // CTEXT_H
