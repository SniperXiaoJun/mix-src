#include "watch.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	WATCH w;

	//w.showFullScreen();
	//w.showMaximized();
	w.show();
	return a.exec();
}
