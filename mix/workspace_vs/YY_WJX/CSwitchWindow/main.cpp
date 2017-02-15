#include "CSwitchWindow.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc,argv);

	CSwitchWindow w;

	w.StartSwitch();

	return a.exec();
}



