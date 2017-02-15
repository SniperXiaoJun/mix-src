#include "crt_cpuview.h"
#include <QtGui/QApplication>

#include "mainwindow.h"

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	MainWindow w;

	//CRT_CPUView w;

	w.show();
	return a.exec();
}
