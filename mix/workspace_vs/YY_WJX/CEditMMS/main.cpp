#include "CWriteMSUI.h"

#include <QtGui/QApplication>
#include <QTextCodec>

int main(int argc, char *argv[])
{
	QTextCodec::setCodecForCStrings(QTextCodec::codecForName("GBK"));
	QApplication a(argc, argv);
	CWriteMSUI w;
	const char * p = "aaaa";
	char * q = (char *)p;
	w.show();
	return a.exec();
}
