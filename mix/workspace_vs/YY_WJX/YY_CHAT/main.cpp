#include "yy_chat.h"
#include <QtGui/QApplication>
#include <QTextCodec>
#include "YY_CHAT_ThreadClient.h"
#include "YY_CHAT_ThreadServer.h"

int main(int argc, char *argv[])
{
	QTextCodec::setCodecForCStrings(QTextCodec::codecForName("GBK"));
	QApplication a(argc, argv);

	YY_CHAT w;
	w.show();

	return a.exec();
}
