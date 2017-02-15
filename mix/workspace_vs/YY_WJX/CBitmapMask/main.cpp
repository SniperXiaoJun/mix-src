#include "CBitmapMask.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	CBitmapMask w;
	w.show();
	return a.exec();
}
