#include "qt_test.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	QT_Test w;
	w.show();
	return a.exec();
}
