#include "clineedit.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	unsigned char * cc = new unsigned char[3];
	cc[1] = '1';
	cc[2] = '2';
	cc[3] = '\0';
	CLineEdit w(cc);
	w.show();
	return a.exec();
}
