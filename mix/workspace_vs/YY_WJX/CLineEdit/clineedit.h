#ifndef CLINEEDIT_H
#define CLINEEDIT_H

#include <QtGui/QMainWindow>
#include "ui_clineedit.h"
#include <QRegExp>

class CLineEdit : public QMainWindow
{
	Q_OBJECT

public:
	CLineEdit(unsigned char * p = NULL, QWidget *parent = 0, Qt::WFlags flags = 0);
	~CLineEdit();

public slots:
	void PrintSLOT();
private:
	Ui::CLineEditClass ui;
	
	QStringList m_StringList;
};

#endif // CLINEEDIT_H
