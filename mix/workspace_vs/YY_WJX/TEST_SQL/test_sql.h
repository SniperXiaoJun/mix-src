#ifndef TEST_SQL_H
#define TEST_SQL_H

#include <QtGui/QMainWindow>
#include "ui_test_sql.h"

class TEST_SQL : public QMainWindow
{
	Q_OBJECT

public:
	TEST_SQL(QWidget *parent = 0, Qt::WFlags flags = 0);
	~TEST_SQL();

private:
	Ui::TEST_SQLClass ui;
};

#endif // TEST_SQL_H
