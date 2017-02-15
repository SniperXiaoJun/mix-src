
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
			QString str("����");

			std::cout << "Straight Output:";
			std::cout << str.toAscii().constData() << std::endl;

			std::cout << "Local Output:";
			std::cout << str.toLocal8Bit().constData() << std::endl;
		}
		{
			QString str = QString::fromLocal8Bit("����");

			std::cout << "Straight Output:";
			std::cout << str.toAscii().constData() << std::endl;

			std::cout << "Local Output:";
			std::cout << str.toLocal8Bit().constData() << std::endl;
		}
	}
	
	
	QString str("��Ը����������ħ�ڰκӣ�Ҳ��Ը����һֻ��ʹ�����衣");
	QPushButton ww(QString::fromLocal8Bit(str.toAscii().constData()));
		ww.show();
	return a.exec();
}
