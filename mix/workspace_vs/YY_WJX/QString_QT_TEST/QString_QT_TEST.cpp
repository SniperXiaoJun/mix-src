/****************************************************************************
****************************************************************************/

#include "QString_QT_TEST.h"
#include <QTime>

QString_QT_TEST::QString_QT_TEST(QWidget *parent)
    : QMainWindow(parent)
{
	ui.setupUi(this);
	
	
	QObject::connect(this->ui.pushButton, SIGNAL(clicked()), this, SLOT(AddOneLine()));
}

QString_QT_TEST::~QString_QT_TEST()
{

}

void QString_QT_TEST::AddOneLine()
{
	QString str = "����һ��\n";

	this->ui.textEdit->append(str);
	this->ui.textEdit->append(QApplication::translate("QString_QT_TEST", "�����ļ�", 0, QApplication::UnicodeUTF8));
	this->ui.textEdit->append(QString::fromLocal8Bit(str.toAscii().constData()));
	this->ui.textEdit->append(QString::fromLocal8Bit("���ܹ��蹤����\n"));
}
