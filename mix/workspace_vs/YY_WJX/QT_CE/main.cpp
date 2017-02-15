#include "MobileSip.h"
#include <QtGui/QApplication>
#include <QFile>
#include <QTextStream>

#include "CSqlDB.h"
#include "Application.h"
#include <QInputContext>

int main(int argc, char *argv[])
{
	Application a(argc, argv);

	//SYSTEM_POWER_STATUS_EX stat;
	//GetSystemPowerStatusEx(&stat, TRUE);
	//int bb = [HKEY_LOCAL_MACHINE\System\State\Phone\Signal Strength];

	//int BatteryLifePercent = stat.BatteryLifePercent;

	//bool b = false;

	//CSqlDB::ConnectToDB();
	//b = CSqlDB::CreateTable_Box();
	//b = CSqlDB::Box_AddItem(1,"Send","date_time", "sign");

	//SBox box;

	//box = CSqlDB::Box_SelectItems().at(0);

	//QString ss = box.sender;
	//QString sss = box.date_time;
	//QString ssss = box.sign;

	MobileSip w;

	a.inputContext()->installEventFilter(&a);

	w.show();
	return a.exec();
}
