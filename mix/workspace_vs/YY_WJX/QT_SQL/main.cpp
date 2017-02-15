#include "qt_sql.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	QT_SQL w;
	w.show();
	return a.exec();
}
