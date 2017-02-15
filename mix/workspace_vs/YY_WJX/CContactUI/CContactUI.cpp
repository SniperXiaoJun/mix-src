#include "CContactUI.h"

#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>

CContactUI::CContactUI(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);
	
	mb.setupMenuBar(this);
	connect(this->ui.pushButton, SIGNAL(clicked()),this, SLOT(SlotShow()));
}

CContactUI::~CContactUI()
{

}

void CContactUI::SlotShow()
{
	//if(ui.tabWidget->currentWidget() == ui.tabE_GRP)
	//{
	//	this->setWindowTitle(ui.listWidgetE_GRP->currentItem()->text());
	//	mb.setupMenuBar(this);
	//}
	//else
	//{
	//	this->setWindowTitle(ui.listWidget->currentItem()->text());
	//	mb.setupMenuBar(this);
	//}
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("Contact.db");
    db.open();

    QSqlQuery query;

#if 0
    query.prepare("create table student(sno integer primary key,sname text,sex text,sage integer,sdept text);");

    query.exec();
#endif



#if 0
    query.prepare("INSERT INTO log(name,msg)"
                  "VALUES (:name,:msg)");
    query.bindValue(":name", "a");
    query.bindValue(":msg", "b");

    query.exec();
#endif

    db.close();
}
