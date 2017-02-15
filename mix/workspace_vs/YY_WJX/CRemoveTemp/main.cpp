#include <QFile>
#include <QDir>
#include <QWidget>
#include <QStringList>
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);

	QDir dir("D:/LQQ");
	QStringList filter;
	filter.append("*.temp");
	filter.append("*.TEMP");
	QStringList strList = dir.entryList(filter);

	QString str;
	int i = 0;

	for(i = 0; i < strList.count(); i++)
	{
		dir.remove(strList.at(i));
		dir.rmdir(strList.at(i));
	}
	
	QWidget w;

	w.setWindowTitle(QString::number(strList.count()));
	//w.setWindowTitle(dir.absolutePath());
	//w.setWindowTitle(strList.at(1));
	
	w.show();
	return a.exec();
}
