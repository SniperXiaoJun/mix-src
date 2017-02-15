#include "CContactUI.h"
#include <QtGui/QApplication>
#include <QTextCodec>

int main(int argc, char *argv[])
{
	QTextCodec::setCodecForCStrings(QTextCodec::codecForName("GBK"));
	QApplication a(argc, argv);
	CContactUI w;
	w.show();
	return a.exec();
}
