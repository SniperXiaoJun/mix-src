
#include <QtCore/QCoreApplication>
#include <QtGui/QApplication>
#include <QTextCodec>
#include <qtgui/QPushButton>
#include <iostream>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	{
		{
			QString str("汉字");

			std::cout << "Straight Output:";
			std::cout << str.toAscii().constData() << std::endl;

			std::cout << "Local Output:";
			std::cout << str.toLocal8Bit().constData() << std::endl;
		}
		{
			QString str = QString::fromLocal8Bit("汉字");

			std::cout << "Straight Output:";
			std::cout << str.toAscii().constData() << std::endl;

			std::cout << "Local Output:";
			std::cout << str.toLocal8Bit().constData() << std::endl;
		}
	}
	
	
	QString str("宁愿看见两个恶魔在拔河，也不愿看见一只天使在跳舞。");
	QPushButton ww(QString::fromLocal8Bit(str.toAscii().constData()));
		ww.show();
	return a.exec();
}
