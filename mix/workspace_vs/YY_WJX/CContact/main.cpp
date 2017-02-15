#include "CContact.h"
#include <QtGui/QApplication>

//typedef unsigned char BYTE;
//typedef int BOOL;
//
//BOOL BlurFindStr(QString &strSource,QString &strFindCell);
int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	CContact w;

	//QString ss("ǿǿ");
	//QString s("q");

	//if(BlurFindStr(ss,s))
	//{
	//	w.setWindowTitle("sfdsad");
	//}
	w.show();


	return a.exec();
}
