#include "ctext.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	CText w;
	w.show();
	return a.exec();
}
