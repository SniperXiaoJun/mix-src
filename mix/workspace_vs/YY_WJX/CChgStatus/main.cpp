#include "cchgstatus.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	CChgStatus w;
	w.show();
	return a.exec();
}
