#include "qtestnetrork.h"
#include <QtGui/QApplication>

#include <QWebView>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);


	QTestNetrork net;

	net.show();

	

	//QWebView * web = new QWebView();

	//web->load(QUrl("http://qt.digia.com//"));

	//web->show();
	return a.exec();
}
