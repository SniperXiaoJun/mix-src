#include "ckeypress.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	CKeyPress w;
	w.show();
	return a.exec();
}
