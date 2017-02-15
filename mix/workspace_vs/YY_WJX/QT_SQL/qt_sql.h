#ifndef QT_SQL_H
#define QT_SQL_H

#include <QtGui/QMainWindow>
#include "ui_qt_sql.h"

class QT_SQL : public QMainWindow
{
	Q_OBJECT

public:
	QT_SQL(QWidget *parent = 0, Qt::WFlags flags = 0);
	~QT_SQL();

private:
	Ui::QT_SQLClass ui;
};

#endif // QT_SQL_H
