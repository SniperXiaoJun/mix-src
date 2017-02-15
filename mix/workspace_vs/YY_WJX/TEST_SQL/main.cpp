#include "test_sql.h"
#include <QtGui/QApplication>
#include "CSqlDB.h"
#include <QTextCodec>

int main(int argc, char *argv[])
{
	//QTextCodec::setCodecForCStrings(QTextCodec::codecForName("GBK"));
	QApplication a(argc, argv);
	TEST_SQL w;

	bool bFlag = false;


	CSqlDB::ConnectToDB();

	bFlag = CSqlDB::CreateTable_Box();

	SBox boxAdd;
	boxAdd.contact = "0";
	boxAdd.date_time = "0";
	boxAdd.id = 2;
	boxAdd.location = "i";
	boxAdd.sender = "s";
	boxAdd.sign = "y";
	boxAdd.type = "s";


	SBox boxChange;
	boxChange.contact = "1";
	boxChange.date_time = "1";
	boxChange.id = 2;
	boxChange.location = "1";
	boxChange.sender = "1";
	boxChange.sign = "1";
	boxChange.type = "1";


	bFlag = CSqlDB::Box_AddItem(boxAdd);

	//SBox from;
	//from.id = 2;

	bFlag = CSqlDB::Box_UpdateItem(boxAdd, boxChange);

	QList<SBox> list;
	list = CSqlDB::Box_SelectItems();

	if(list.count())
	{
		SBox boxSel = list.at(0);
	}


	w.show();
	return a.exec();
}
