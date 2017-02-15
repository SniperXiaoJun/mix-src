#include "cres.h"
#include <QtGui/QApplication>

int BlurFindStr(QString &,QString &);

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	CRes w;

	QString str1("李强强");
	QString str2("lqq");
	if(BlurFindStr(str1,str2))
	{
		w.setWindowTitle(QString::number(QString("强强").count()));
	}
	else
	{
		w.setWindowTitle("False");
	}

	w.show();
	return a.exec();
}
