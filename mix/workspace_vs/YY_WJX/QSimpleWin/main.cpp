#include "csimple.h"
#include "common.h"

#include <QTextStream>
#include <QFile.h>
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	CSimple w;

	w.showFullScreen();
	return a.exec();
}
