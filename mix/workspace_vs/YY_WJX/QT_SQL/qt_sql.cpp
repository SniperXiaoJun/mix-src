#include "qt_sql.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include "CSqlDB.h"



QT_SQL::QT_SQL(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	bool b = false;
	
	b = CSqlDB::CreateTable_Message();
	if(b)
	{
		b = false;
	}

	b =  CSqlDB::CreateTable_Box();
	if(b)
	{
		b = false;
	}



	b = CSqlDB::CreateTable_Contact();
	if(b)
	{
		b = false;
	}

	b =  CSqlDB::DropTable_Contact();
	if(b)
	{
		b = false;
	}














	QString str[6][2] = {QString("a"),QString("b"),
		QString("c"), QString("d"),QString("e"),QString("b"),
		QString("c"),QString("asdf"), QString("44"),
		QString("tt"),QString("21")};

	b = CSqlDB::Box_UpdateItem(str[0],str[1],str[2],str[3],str[4],str[5]);
	if(b)
	{
		b = false;
	}

	b =  CSqlDB::Box_UpdateSign("a");
	if(b)
	{
		b = false;
	}


	b = CSqlDB::Message_AddItem("a","b","c","d");
	if(b)
	{
		b = false;
	}

	b =  CSqlDB::Box_AddItem("a","b","c","d","e","f");
	if(b)
	{
		b = false;
	}


	QList<SMessage> list;

	list =  CSqlDB::Message_SelectItems();
	if(list.count())
	{
		b = false;
	}

	QList<SBox> list2;

	list2 =  CSqlDB::Box_SelectItems("a","b","c","d","e","f");
	if(list2.count())
	{
		b = false;
	}




	b = CSqlDB::Message_DelItem("a","b","c","d");
	if(b)
	{
		b = false;
	}

	b =  CSqlDB::Box_DelItem("a","b","c","d","e","f");
	if(b)
	{
		b = false;
	}

















	b =  CSqlDB::DropTable_Message();
	if(b)
	{
		b = false;
	}

	b =  CSqlDB::DropTable_Box();
	if(b)
	{
		b = false;
	}
}

QT_SQL::~QT_SQL()
{

}




