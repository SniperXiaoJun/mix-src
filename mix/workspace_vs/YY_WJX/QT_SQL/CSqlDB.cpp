#include "CSqlDB.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QVariant>
#include <QMessageBox>

void CSqlDB::ConnectToDB()
{
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("taiji.db");

    db.open();
}

void CSqlDB::DisConnectToDB()
{
    QSqlDatabase db = QSqlDatabase::QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("taiji.db");

    db.close();
    db.removeDatabase("QSQLITE");
}

CSqlDB::CSqlDB()
{

}

CSqlDB::~CSqlDB()
{

}

bool CSqlDB::CreateTable_Message()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("create table message(id integer,type text,name text,content text);");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}
bool CSqlDB::CreateTable_Box()
{
    bool ret = false;

    bool ret2 = CSqlDB::CreateTable_Message();

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare(
        "create table box(id integer primary key,sender text,date_time text,sign text,type text, location text, contact text);");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret && ret2;
}

bool CSqlDB::CreateTable_Contact()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare(
        "create table contact(id integer primary key,tel text,name text,cell text,note text,group_location text,encrypt text);");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::CreateTable_Group()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("create table contactgroup(id integer primary key,type text,name text);");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::CreateTable_EBold()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare(
        "create table ebold(id integer primary key,fid integer, start_id integer,next_id integer, name text, type text, title text, content text, date_time text);");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::CreateTable_Account()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare(
        "create table account(id integer primary key, id_number text, name text, acc_number text, note text);");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Message_AddItem(int id, QString type, QString name, QString content)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("INSERT INTO message(id,type,name,content)"
        "VALUES (:id,:type,:name,:content)");

    query.bindValue(":id", id);
    query.bindValue(":type", type);
    query.bindValue(":name", name);
    query.bindValue(":content", content);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Account_AddItem(int id, QString id_number, QString name, QString acc_number,
    QString note)
{
    bool ret = false;
    
    id = CSqlDB::Account_Select_Max_ID();

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("INSERT INTO account(id,id_number,name,acc_number,note)"
        "VALUES (:id,:id_number,:name,:acc_number,:note)");

    query.bindValue(":id", id);
    query.bindValue(":id_number", id_number);
    query.bindValue(":name", name);
    query.bindValue(":acc_number", acc_number);
    query.bindValue(":note", note);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Group_AddItem(int id, QString type, QString name)
{
    bool ret = false;

    id = CSqlDB::Group_Select_Max_ID();

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("INSERT INTO contactgroup(id,type,name)"
        "VALUES (:id,:type,:name)");

    query.bindValue(":id", id);
    query.bindValue(":type", type);
    query.bindValue(":name", name);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::EBold_AddItem(int id, int fid, int start_id, int next_id, QString name, QString type,
    QString title, QString content, QString date_time)
{
    bool ret = false;

    id = CSqlDB::EBold_Select_Max_ID();

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("INSERT INTO ebold(id,fid,start_id,next_id,name,type,title,content,date_time)"
        "VALUES (:id,:fid,:start_id,:next_id,:name,:type,:title,:content,:date_time)");

    query.bindValue(":id", id);
    query.bindValue(":fid", fid);
    query.bindValue(":start_id", start_id);
    query.bindValue(":next_id", next_id);
    query.bindValue(":name", name);
    query.bindValue(":type", type);
    query.bindValue(":title", title);
    query.bindValue(":content", content);
    query.bindValue(":date_time", date_time);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Message_DelItem(int id, QString type, QString name, QString content)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("delete from message");

    bool andAppend = false; //是否要加AND

    if (id > 0 || type.length() > 0 || name .length() > 0 || content.length() > 0) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (type.length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name.length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (content.length() > 0) {
        if (andAppend) {
            queryString += " and content=";
            queryString += "\"";
            queryString += content;
            queryString += "\"";
        }
        else {
            queryString += "content=";
            queryString += "\"";
            queryString += content;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Account_DelItem(int id, QString id_number, QString name, QString acc_number,
    QString note)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("delete from account");

    bool andAppend = false; //是否要加AND

    if (id > 0 || id_number.length() > 0 || name .length() > 0 || acc_number.length() > 0, note.length()
        > 0) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (id_number.length() > 0) {
        if (andAppend) {
            queryString += " and id_number=";
            queryString += "\"";
            queryString += id_number;
            queryString += "\"";
        }
        else {
            queryString += "id_number=";
            queryString += "\"";
            queryString += id_number;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name.length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (acc_number.length() > 0) {
        if (andAppend) {
            queryString += " and acc_number=";
            queryString += "\"";
            queryString += acc_number;
            queryString += "\"";
        }
        else {
            queryString += "acc_number=";
            queryString += "\"";
            queryString += acc_number;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (note.length() > 0) {
        if (andAppend) {
            queryString += " and note=";
            queryString += "\"";
            queryString += note;
            queryString += "\"";
        }
        else {
            queryString += "note=";
            queryString += "\"";
            queryString += note;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    QMessageBox::warning(0,"a",queryString);
    
    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Group_DelItem(int id, QString type, QString name)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("delete from contactgroup");

    bool andAppend = false; //是否要加AND

    if (id > 0 || type.length() > 0 || name .length() > 0) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (type.length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name.length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::EBold_DelItem(int id)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("delete from ebold");

    if (id > 0) {
        queryString += " where ";
        queryString += "id=";
        queryString += QString::number(id);
    }

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Message_UpdateItem(int * id, QString * type, QString * name, QString * content)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("update message");

    bool andAppend = false;

    if (id[0] > 0 || type[0].length() > 0 || name[0].length() > 0 || content[0].length() > 0) {
        queryString += " set ";
    }
    else {
        return true;
    }

    if (id[0] > 0) {
        queryString += "id=";
        queryString += QString::number(id[0]);
        andAppend = true;
    }

    if (type[0].length() > 0) {
        if (andAppend) {
            queryString += ",type=";
            queryString += "\"";
            queryString += type[0];
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name[0].length() > 0) {
        if (andAppend) {
            queryString += ",name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (content[0].length() > 0) {
        if (andAppend) {
            queryString += ",content=";
            queryString += "\"";
            queryString += content[0];
            queryString += "\"";
        }
        else {
            queryString += "content=";
            queryString += "\"";
            queryString += content[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    andAppend = false;

    if (id[1] > 0 || type[1].length() > 0 || name[1].length() > 0 || content[1].length() > 0) {
        queryString += " where ";
    }

    if (id[1] > 0) {
        queryString += "id=";
        queryString += QString::number(id[1]);
        andAppend = true;
    }

    if (type[1].length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type[1];
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name[1].length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (content[1].length() > 0) {
        if (andAppend) {
            queryString += " and content=";
            queryString += "\"";
            queryString += content[1];
            queryString += "\"";
        }
        else {
            queryString += "content=";
            queryString += "\"";
            queryString += content[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Group_UpdateItem(int * id, QString * type, QString * name)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("update contactgroup");

    bool andAppend = false;

    if (id[0] > 0 || type[0].length() > 0 || name[0].length() > 0) {
        queryString += " set ";
    }
    else {
        return true;
    }

    if (id[0] > 0) {
        queryString += "id=";
        queryString += QString::number(id[0]);
        andAppend = true;
    }

    if (type[0].length() > 0) {
        if (andAppend) {
            queryString += ",type=";
            queryString += "\"";
            queryString += type[0];
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name[0].length() > 0) {
        if (andAppend) {
            queryString += ",name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    andAppend = false;

    if (id[1] > 0 || type[1].length() > 0 || name[1].length() > 0) {
        queryString += " where ";
    }

    if (id[1] > 0) {
        queryString += "id=";
        queryString += QString::number(id[1]);
        andAppend = true;
    }

    if (type[1].length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type[1];
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name[1].length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Account_UpdateItem(int * id, QString * id_number, QString * name,
    QString * acc_number, QString * note)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("update account");

    bool andAppend = false;

    if (id[0] > 0 || id_number[0].length() > 0 || name[0].length() > 0 || acc_number[0].length()
        > 0 || note[0].length() > 0) {
        queryString += " set ";
    }
    else {
        return true;
    }

    if (id[0] > 0) {
        queryString += "id=";
        queryString += QString::number(id[0]);
        andAppend = true;
    }

    if (id_number[0].length() > 0) {
        if (andAppend) {
            queryString += ",id_number=";
            queryString += "\"";
            queryString += id_number[0];
            queryString += "\"";
        }
        else {
            queryString += "id_number=";
            queryString += "\"";
            queryString += id_number[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name[0].length() > 0) {
        if (andAppend) {
            queryString += ",name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (acc_number[0].length() > 0) {
        if (andAppend) {
            queryString += ",acc_number=";
            queryString += "\"";
            queryString += acc_number[0];
            queryString += "\"";
        }
        else {
            queryString += "acc_number=";
            queryString += "\"";
            queryString += acc_number[0];
            queryString += "\"";
        }
        andAppend = true;
    }
    
    if (note[0].length() > 0) {
        if (andAppend) {
            queryString += ",note=";
            queryString += "\"";
            queryString += note[0];
            queryString += "\"";
        }
        else {
            queryString += "note=";
            queryString += "\"";
            queryString += note[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    andAppend = false;

    if (id[1] > 0 || id_number[1].length() > 0 || name[1].length() > 0 || acc_number[1].length()
        > 0 || note[1].length() > 0) {
        queryString += " where ";
    }

    if (id[1] > 0) {
        queryString += "id=";
        queryString += QString::number(id[1]);
        andAppend = true;
    }

    if (id_number[1].length() > 0) {
        if (andAppend) {
            queryString += " and id_number=";
            queryString += "\"";
            queryString += id_number[1];
            queryString += "\"";
        }
        else {
            queryString += "id_number=";
            queryString += "\"";
            queryString += id_number[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name[1].length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (acc_number[1].length() > 0) {
        if (andAppend) {
            queryString += " and acc_number=";
            queryString += "\"";
            queryString += acc_number[1];
            queryString += "\"";
        }
        else {
            queryString += "acc_number=";
            queryString += "\"";
            queryString += acc_number[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (note[1].length() > 0) {
        if (andAppend) {
            queryString += " and note=";
            queryString += "\"";
            queryString += note[1];
            queryString += "\"";
        }
        else {
            queryString += "note=";
            queryString += "\"";
            queryString += note[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::EBold_UpdateItem(int * id, int * fid, int * start_id, int * next_id, QString * name,
    QString * type, QString * title, QString * content, QString * date_time)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("update ebold");

    bool andAppend = false;

    if (id[0] > 0 || fid[0] > 0 || start_id[0] > 0 || next_id[0] > 0 || name[0].length() > 0
        || type[0].length() > 0 || title[0].length() > 0 || content[0].length() > 0
        || date_time[0].length() > 0) {
        queryString += " set ";
    }
    else {
        return true;
    }

    if (id[0] > 0) {
        queryString += "id=";
        queryString += QString::number(id[0]);
        andAppend = true;
    }

    if (fid[0] > 0) {
        if (andAppend) {
            queryString += ",fid=";
            queryString += QString::number(fid[0]);
        }
        else {
            queryString += "fid=";
            queryString += QString::number(fid[0]);
        }
        andAppend = true;
    }

    if (start_id[0] > 0) {
        if (andAppend) {
            queryString += ",start_id=";
            queryString += QString::number(start_id[0]);
        }
        else {
            queryString += "start_id=";
            queryString += QString::number(start_id[0]);
        }
        andAppend = true;
    }

    if (next_id[0] > 0) {
        if (andAppend) {
            queryString += ",next_id=";
            queryString += QString::number(next_id[0]);
        }
        else {
            queryString += "next_id=";
            queryString += QString::number(next_id[0]);
        }
        andAppend = true;
    }

    if (name[0].length() > 0) {
        if (andAppend) {
            queryString += ",name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (type[0].length() > 0) {
        if (andAppend) {
            queryString += ",type=";
            queryString += "\"";
            queryString += type[0];
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (title[0].length() > 0) {
        if (andAppend) {
            queryString += ",title=";
            queryString += "\"";
            queryString += title[0];
            queryString += "\"";
        }
        else {
            queryString += "title=";
            queryString += "\"";
            queryString += title[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (content[0].length() > 0) {
        if (andAppend) {
            queryString += ",content=";
            queryString += "\"";
            queryString += content[0];
            queryString += "\"";
        }
        else {
            queryString += "content=";
            queryString += "\"";
            queryString += content[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (date_time[0].length() > 0) {
        if (andAppend) {
            queryString += ",date_time=";
            queryString += "\"";
            queryString += date_time[0];
            queryString += "\"";
        }
        else {
            queryString += "date_time=";
            queryString += "\"";
            queryString += date_time[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    andAppend = false;

    if (id[1] > 0 || fid[1] > 0 || start_id[1] > 0 || next_id[1] > 0 || name[1].length() > 0
        || type[1].length() > 0 || title[1].length() > 0 || content[1].length() > 0
        || date_time[1].length() > 0) {
        queryString += " where ";
    }

    if (id[1] > 0) {
        queryString += "id=";
        queryString += QString::number(id[1]);
        andAppend = true;
    }

    if (fid[1] > 0) {
        if (andAppend) {
            queryString += " and fid=";
            queryString += QString::number(fid[1]);
        }
        else {
            queryString += "fid=";
            queryString += QString::number(fid[1]);
        }
        andAppend = true;
    }

    if (start_id[1] > 0) {
        if (andAppend) {
            queryString += " and start_id=";
            queryString += QString::number(start_id[1]);
        }
        else {
            queryString += "start_id=";
            queryString += QString::number(start_id[1]);
        }
        andAppend = true;
    }

    if (next_id[1] > 0) {
        if (andAppend) {
            queryString += " and next_id=";
            queryString += QString::number(next_id[1]);
        }
        else {
            queryString += "next_id=";
            queryString += QString::number(next_id[1]);
        }
        andAppend = true;
    }

    if (name[1].length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (type[1].length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type[1];
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (title[1].length() > 0) {
        if (andAppend) {
            queryString += " and title=";
            queryString += "\"";
            queryString += title[1];
            queryString += "\"";
        }
        else {
            queryString += "title=";
            queryString += "\"";
            queryString += title[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (content[1].length() > 0) {
        if (andAppend) {
            queryString += " and content=";
            queryString += "\"";
            queryString += content[1];
            queryString += "\"";
        }
        else {
            queryString += "content=";
            queryString += "\"";
            queryString += content[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (date_time[1].length() > 0) {
        if (andAppend) {
            queryString += " and date_time=";
            queryString += "\"";
            queryString += date_time[1];
            queryString += "\"";
        }
        else {
            queryString += "date_time=";
            queryString += "\"";
            queryString += date_time[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

QList<SMessage> CSqlDB::Message_SelectItems(int id, QString type, QString name, QString content)
{
    QList<SMessage> list;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("SELECT * FROM message");

    bool andAppend = false;

    if (id > 0 || type.length() > 0 || name .length() > 0 || content.length() > 0) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (type.length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name.length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (content.length() > 0) {
        if (andAppend) {
            queryString += " and content=";
            queryString += "\"";
            queryString += content;
            queryString += "\"";
        }
        else {
            queryString += "content=";
            queryString += "\"";
            queryString += content;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);
    query.exec();

    while (query.next()) {
        int sid = query.value(0).toInt();
        QString stype = query.value(1).toString();
        QString sname = query.value(2).toString();
        QString scontent = query.value(3).toString();

        SMessage msgtmp;

        msgtmp.mid = sid;
        msgtmp.name = sname;
        msgtmp.type = stype;
        msgtmp.content = scontent;

        list.append(msgtmp);
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    return list;
}

QList<SGroup> CSqlDB::Group_SelectItems(int id, QString type, QString name)
{
    QList<SGroup> list;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("SELECT * FROM contactgroup");

    bool andAppend = false;

    if (id > 0 || type.length() > 0 || name .length() > 0) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (type.length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name.length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);
    query.exec();

    while (query.next()) {
        int sid = query.value(0).toInt();
        QString stype = query.value(1).toString();
        QString sname = query.value(2).toString();

        SGroup msgtmp;

        msgtmp.mid = sid;
        msgtmp.name = sname;
        msgtmp.type = stype;

        list.append(msgtmp);
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    return list;
}

QList<SAccount> CSqlDB::Account_SelectItems(int id, QString id_number, QString name,
    QString acc_number, QString note)
{
    QList<SAccount> list;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("SELECT * FROM account");

    bool andAppend = false;

    if (id > 0 || id_number.length() > 0 || name .length() > 0 || acc_number.length() > 0
        || note .length() > 0) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (id_number.length() > 0) {
        if (andAppend) {
            queryString += " and id_number=";
            queryString += "\"";
            queryString += id_number;
            queryString += "\"";
        }
        else {
            queryString += "id_number=";
            queryString += "\"";
            queryString += id_number;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name.length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (acc_number.length() > 0) {
        if (andAppend) {
            queryString += " and acc_number=";
            queryString += "\"";
            queryString += acc_number;
            queryString += "\"";
        }
        else {
            queryString += "acc_number=";
            queryString += "\"";
            queryString += acc_number;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (note.length() > 0) {
        if (andAppend) {
            queryString += " and note=";
            queryString += "\"";
            queryString += note;
            queryString += "\"";
        }
        else {
            queryString += "note=";
            queryString += "\"";
            queryString += note;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);
    query.exec();

    while (query.next()) {
        int sid = query.value(0).toInt();
        QString sid_number = query.value(1).toString();
        QString sname = query.value(2).toString();
        QString sacc_number = query.value(3).toString();
        QString snote = query.value(4).toString();

        SAccount msgtmp;

        msgtmp.id = sid;
        msgtmp.name = sname;
        msgtmp.acc_number = sacc_number;
        msgtmp.id_number = sid_number;
        msgtmp.note = snote;

        list.append(msgtmp);
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    return list;
}

QList<SEBold> CSqlDB::EBold_SelectItems(int id, int fid, int start_id, int next_id, QString name,
    QString type, QString title, QString content, QString date_time)
{
    QList<SEBold> list;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("SELECT * FROM ebold");

    bool andAppend = false;

    if (id > 0 || fid > 0 || start_id > 0 || next_id > 0 || name.length() > 0 || type.length() > 0
        || title.length() > 0 || content.length() > 0 || date_time.length() > 0) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (fid > 0) {
        if (andAppend) {
            queryString += " and fid=";
            queryString += QString::number(fid);
        }
        else {
            queryString += "fid=";
            queryString += QString::number(fid);
        }
        andAppend = true;
    }

    if (start_id > 0) {
        if (andAppend) {
            queryString += " and start_id=";
            queryString += QString::number(start_id);
        }
        else {
            queryString += "start_id=";
            queryString += QString::number(start_id);
        }
        andAppend = true;
    }

    if (next_id > 0) {
        if (andAppend) {
            queryString += " and next_id=";
            queryString += QString::number(next_id);
        }
        else {
            queryString += "next_id=";
            queryString += QString::number(next_id);
        }
        andAppend = true;
    }

    if (name.length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (type.length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (title.length() > 0) {
        if (andAppend) {
            queryString += " and title=";
            queryString += "\"";
            queryString += title;
            queryString += "\"";
        }
        else {
            queryString += "title=";
            queryString += "\"";
            queryString += title;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (content.length() > 0) {
        if (andAppend) {
            queryString += " and content=";
            queryString += "\"";
            queryString += content;
            queryString += "\"";
        }
        else {
            queryString += "content=";
            queryString += "\"";
            queryString += content;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (date_time.length() > 0) {
        if (andAppend) {
            queryString += " and date_time=";
            queryString += "\"";
            queryString += date_time;
            queryString += "\"";
        }
        else {
            queryString += "date_time=";
            queryString += "\"";
            queryString += date_time;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);
    query.exec();

    while (query.next()) {
        int sid = query.value(0).toInt();
        int sfid = query.value(1).toInt();
        int sstart_id = query.value(2).toInt();
        int snext_id = query.value(3).toInt();

        QString sname = query.value(4).toString();
        QString stype = query.value(5).toString();
        QString stitle = query.value(6).toString();
        QString scontent = query.value(7).toString();
        QString sdate_time = query.value(8).toString();

        SEBold msgtmp;

        msgtmp.id = sid;
        msgtmp.fid = sfid;
        msgtmp.start_id = sstart_id;
        msgtmp.next_id = snext_id;

        msgtmp.name = sname;
        msgtmp.type = stype;
        msgtmp.title = stitle;
        msgtmp.content = scontent;
        msgtmp.date_time = sdate_time;

        list.append(msgtmp);
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    return list;
}

bool CSqlDB::Box_AddItem(int id, QString sender, QString date_time, QString sign, QString type,
    QString location, QString contact)
{
    bool ret = false;

    QList<SContact> conList;

    SContact con;

    con.id = -1;
    con.cell = sender;

    conList = CSqlDB::Contact_SelectItems(con);

    if (conList.count() > 0) {
        contact = conList.at(0).name;
    }

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("INSERT INTO box(id,sender,date_time,sign,type,location,contact)"
        "VALUES (:id,:sender,:date_time,:sign,:type,:location,:contact)");

    query.bindValue(":id", id);
    query.bindValue(":sender", sender);
    query.bindValue(":date_time", date_time);
    query.bindValue(":sign", sign);
    query.bindValue(":type", type);
    query.bindValue(":location", location);
    query.bindValue(":contact", contact);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Box_DelItem(int id, QString sender, QString date_time, QString sign, QString type,
    QString location, QString contact)
{
    bool ret = false;

    CSqlDB::Message_DelItem(id);

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("delete from box");

    bool andAppend = false;

    if (id > 0 || sender.length() > 0 || date_time.length() > 0 || sign.length() > 0
        || type.length() > 0 || location.length() > 0 || contact.length() > 0) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (sender.length() > 0) {
        if (andAppend) {
            queryString += " and sender=";
            queryString += "\"";
            queryString += sender;
            queryString += "\"";
        }
        else {
            queryString += "sender=";
            queryString += "\"";
            queryString += sender;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (date_time.length() > 0) {
        if (andAppend) {
            queryString += " and date_time=";
            queryString += "\"";
            queryString += date_time;
            queryString += "\"";
        }
        else {
            queryString += "date_time=";
            queryString += "\"";
            queryString += date_time;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (sign.length() > 0) {
        if (andAppend) {
            queryString += " and sign=";
            queryString += "\"";
            queryString += sign;
            queryString += "\"";
        }
        else {
            queryString += "sign=";
            queryString += "\"";
            queryString += sign;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (type.length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (location.length() > 0) {
        if (andAppend) {
            queryString += " and location=";
            queryString += "\"";
            queryString += location;
            queryString += "\"";
        }
        else {
            queryString += "location=";
            queryString += "\"";
            queryString += location;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (contact.length() > 0) {
        if (andAppend) {
            queryString += " and contact=";
            queryString += "\"";
            queryString += contact;
            queryString += "\"";
        }
        else {
            queryString += "contact=";
            queryString += "\"";
            queryString += contact;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Box_UpdateItem(int * id, QString * sender, QString * date_time, QString * sign,
    QString * type, QString * location, QString * contact)
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("update box");

    bool andAppend = false;

    if (id[0] > 0 || sender[0].length() > 0 || date_time[0].length() > 0 || sign[0].length() > 0
        || type[0].length() > 0 || location[0].length() > 0 || contact[0].length() > 0) {
        queryString += " set ";
    }
    else {
        return true;
    }

    if (id[0] > 0) {
        queryString += "id=";
        queryString += QString::number(id[0]);
        andAppend = true;
    }

    if (sender[0].length() > 0) {
        if (andAppend) {
            queryString += ",sender=";
            queryString += "\"";
            queryString += sender[0];
            queryString += "\"";
        }
        else {
            queryString += "sender=";
            queryString += "\"";
            queryString += sender[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (date_time[0].length() > 0) {
        if (andAppend) {
            queryString += ",date_time=";
            queryString += "\"";
            queryString += date_time[0];
            queryString += "\"";
        }
        else {
            queryString += "date_time=";
            queryString += "\"";
            queryString += date_time[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (sign[0].length() > 0) {
        if (andAppend) {
            queryString += ",sign=";
            queryString += "\"";
            queryString += sign[0];
            queryString += "\"";
        }
        else {
            queryString += "sign=";
            queryString += "\"";
            queryString += sign[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (type[0].length() > 0) {
        if (andAppend) {
            queryString += ",type=";
            queryString += "\"";
            queryString += type[0];
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (location[0].length() > 0) {
        if (andAppend) {
            queryString += ",location=";
            queryString += "\"";
            queryString += location[0];
            queryString += "\"";
        }
        else {
            queryString += "location=";
            queryString += "\"";
            queryString += location[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (contact[0].length() > 0) {
        if (andAppend) {
            queryString += ",contact=";
            queryString += "\"";
            queryString += contact[0];
            queryString += "\"";
        }
        else {
            queryString += "contact=";
            queryString += "\"";
            queryString += contact[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    andAppend = false;

    if (id[1] > 0 || sender[1].length() > 0 || date_time[1].length() > 0 || sign[1].length() > 0
        || type[1].length() > 0 || location[1].length() > 0 || contact[1].length() > 0) {
        queryString += " where ";
    }

    if (id[1] > 0) {
        queryString += "id=";
        queryString += QString::number(id[1]);
        andAppend = true;
    }

    if (sender[1].length() > 0) {
        if (andAppend) {
            queryString += " and sender=";
            queryString += "\"";
            queryString += sender[1];
            queryString += "\"";
        }
        else {
            queryString += "sender=";
            queryString += "\"";
            queryString += sender[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (date_time[1].length() > 0) {
        if (andAppend) {
            queryString += " and date_time=";
            queryString += "\"";
            queryString += date_time[1];
            queryString += "\"";
        }
        else {
            queryString += "date_time=";
            queryString += "\"";
            queryString += date_time[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (sign[1].length() > 0) {
        if (andAppend) {
            queryString += " and sign=";
            queryString += "\"";
            queryString += sign[1];
            queryString += "\"";
        }
        else {
            queryString += "sign=";
            queryString += "\"";
            queryString += sign[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (type[1].length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type[1];
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (location[1].length() > 0) {
        if (andAppend) {
            queryString += " and location=";
            queryString += "\"";
            queryString += location[1];
            queryString += "\"";
        }
        else {
            queryString += "location=";
            queryString += "\"";
            queryString += location[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (contact[1].length() > 0) {
        if (andAppend) {
            queryString += " and contact=";
            queryString += "\"";
            queryString += contact[1];
            queryString += "\"";
        }
        else {
            queryString += "contact=";
            queryString += "\"";
            queryString += contact[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

QList<SBox> CSqlDB::Box_SelectItems(int id, QString sender, QString date_time, QString sign,
    QString type, QString location, QString contact)
{
    QList<SBox> list;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("select * from box");

    bool andAppend = false;

    if (id > 0 || sender.length() > 0 || date_time.length() > 0 || sign.length() > 0
        || type.length() > 0 || location.length() > 0 || contact.length() > 0) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (sender.length() > 0) {
        if (andAppend) {
            queryString += " and sender=";
            queryString += "\"";
            queryString += sender;
            queryString += "\"";
        }
        else {
            queryString += "sender=";
            queryString += "\"";
            queryString += sender;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (date_time.length() > 0) {
        if (andAppend) {
            queryString += " and date_time=";
            queryString += "\"";
            queryString += date_time;
            queryString += "\"";
        }
        else {
            queryString += "date_time=";
            queryString += "\"";
            queryString += date_time;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (sign.length() > 0) {
        if (andAppend) {
            queryString += " and sign=";
            queryString += "\"";
            queryString += sign;
            queryString += "\"";
        }
        else {
            queryString += "sign=";
            queryString += "\"";
            queryString += sign;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (type.length() > 0) {
        if (andAppend) {
            queryString += " and type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        else {
            queryString += "type=";
            queryString += "\"";
            queryString += type;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (location.length() > 0) {
        if (andAppend) {
            queryString += " and location=";
            queryString += "\"";
            queryString += location;
            queryString += "\"";
        }
        else {
            queryString += "location=";
            queryString += "\"";
            queryString += location;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (contact.length() > 0) {
        if (andAppend) {
            queryString += " and contact=";
            queryString += "\"";
            queryString += contact;
            queryString += "\"";
        }
        else {
            queryString += "contact=";
            queryString += "\"";
            queryString += contact;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);
    query.exec();

    while (query.next()) {
        int sid = query.value(0).toInt();
        QString ssender = query.value(1).toString();
        QString sdate_time = query.value(2).toString();
        QString ssign = query.value(3).toString();
        QString stype = query.value(4).toString();
        QString slocation = query.value(5).toString();
        QString scontact = query.value(6).toString();

        SBox boxtmp;

        boxtmp.id = sid;
        boxtmp.sender = ssender;
        boxtmp.date_time = sdate_time;
        boxtmp.type = stype;
        boxtmp.sign = ssign;
        boxtmp.location = slocation;
        boxtmp.contact = scontact;

        list.append(boxtmp);
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    return list;
}

bool CSqlDB::DropTable_Message()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("drop table message");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::DropTable_Box()
{
    bool ret = false;
    bool ret2 = CSqlDB::DropTable_Message();

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("drop table box");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret && ret2;

}

bool CSqlDB::DropTable_Contact()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("drop table contact");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::DropTable_Group()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("drop table contactgroup");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::DropTable_EBold()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("drop table ebold");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::DropTable_Account()
{
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("drop table account");

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Box_UpdateSign(int id)
{
    bool ret1 = false;
    bool ret2 = false;
    bool ret = false;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("update box");

    queryString += " set ";

    queryString += "sign=";
    queryString += "\"";
    queryString += "y";
    queryString += "\"";

    queryString += " where ";

    queryString += "id=";
    queryString += QString::number(id);

    queryString += " and sign=";
    queryString += "\"";
    queryString += "n";
    queryString += "\"";

    query.prepare(queryString);

    ret1 = query.exec();

    QString queryStr = ("update box");

    queryStr += " set ";

    queryStr += "sign=";
    queryStr += "\"";
    queryStr += "n";
    queryStr += "\"";

    queryStr += " where ";

    queryString += "id=";
    queryString += QString::number(id);

    queryStr += " and sign=";
    queryStr += "\"";
    queryStr += "y";
    queryStr += "\"";

    query.prepare(queryStr);

    ret2 = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    ret = ret1 && ret2;
    return ret;
}

bool CSqlDB::Contact_AddItem(int id, QString tel, QString name, QString cell, QString note,
    QString group_location, QString encrypt)
{
    bool ret = false;

    id = CSqlDB::Contact_Select_Max_ID();

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("INSERT INTO contact(id,tel,name,cell,note,group_location,encrypt)"
        "VALUES (:id,:tel,:name,:cell,:note,:group_location,:encrypt)");

    query.bindValue(":id", id);
    query.bindValue(":tel", tel);
    query.bindValue(":name", name);
    query.bindValue(":cell", cell);
    query.bindValue(":note", note);
    query.bindValue(":group_location", group_location);
    query.bindValue(":encrypt", encrypt);

    ret = query.exec();

    if (ret) {
        CSqlDB::Box_UpdateContact(cell, name);
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Contact_DelItem(int id, QString tel, QString name, QString cell, QString note,
    QString group_location, QString encrypt)
{
    bool ret = false;

    SContact con;

    con.id = -1;

    QList<SContact> conList;

    conList = CSqlDB::Contact_SelectItems(id);

    if (conList.count() > 0) {
        con.cell = conList.at(0).cell;
    }

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("delete from contact");

    bool andAppend = false;

    if (id > 0 || tel.length() > 0 || name.length() > 0 || cell.length() > 0 || note.length() > 0
        || group_location.length() > 0 || encrypt.length()) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (tel.length() > 0) {
        if (andAppend) {
            queryString += " and tel=";
            queryString += "\"";
            queryString += tel;
            queryString += "\"";
        }
        else {
            queryString += "tel=";
            queryString += "\"";
            queryString += tel;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name.length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (cell.length() > 0) {
        if (andAppend) {
            queryString += " and cell=";
            queryString += "\"";
            queryString += cell;
            queryString += "\"";
        }
        else {
            queryString += "cell=";
            queryString += "\"";
            queryString += cell;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (note.length() > 0) {
        if (andAppend) {
            queryString += " and note=";
            queryString += "\"";
            queryString += note;
            queryString += "\"";
        }
        else {
            queryString += "note=";
            queryString += "\"";
            queryString += note;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (group_location.length() > 0) {
        if (andAppend) {
            queryString += " and group_location=";
            queryString += "\"";
            queryString += group_location;
            queryString += "\"";
        }
        else {
            queryString += "group_location=";
            queryString += "\"";
            queryString += group_location;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (encrypt.length() > 0) {
        if (andAppend) {
            queryString += " and encrypt=";
            queryString += "\"";
            queryString += encrypt;
            queryString += "\"";
        }
        else {
            queryString += "encrypt=";
            queryString += "\"";
            queryString += encrypt;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    if (ret) {
        conList = CSqlDB::Contact_SelectItems(con);

        if (conList.count() > 0) {
            con.name = conList.at(0).name;
        }

        CSqlDB::Box_UpdateContact(con.cell, con.name);
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

bool CSqlDB::Contact_UpdateItem(int * id, QString * tel, QString * name, QString * cell,
    QString * note, QString * group_location, QString * encrypt)
{
    bool ret = false;

    SContact con;
    QList<SContact> conList;

    conList = CSqlDB::Contact_SelectItems(id[1]);

    if (conList.count() > 0) {
        con.cell = conList.at(0).cell;
        con.name = conList.at(0).name;
    }

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("update contact");

    bool andAppend = false;

    if (id[0] > 0 || tel[0].length() > 0 || name[0].length() > 0 || cell[0].length() > 0
        || note[0].length() > 0 || group_location[0].length() > 0 || encrypt[0].length() > 0) {
        queryString += " set ";
    }
    else {
        return true;
    }

    if (id[0] > 0) {
        queryString += "id=";
        queryString += QString::number(id[0]);
        andAppend = true;
    }

    if (tel[0].length() > 0) {
        if (andAppend) {
            queryString += ",tel=";
            queryString += "\"";
            queryString += tel[0];
            queryString += "\"";
        }
        else {
            queryString += "tel=";
            queryString += "\"";
            queryString += tel[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name[0].length() > 0) {
        if (andAppend) {
            queryString += ",name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (cell[0].length() > 0) {
        if (andAppend) {
            queryString += ",cell=";
            queryString += "\"";
            queryString += cell[0];
            queryString += "\"";
        }
        else {
            queryString += "cell=";
            queryString += "\"";
            queryString += cell[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (note[0].length() > 0) {
        if (andAppend) {
            queryString += ",note=";
            queryString += "\"";
            queryString += note[0];
            queryString += "\"";
        }
        else {
            queryString += "note=";
            queryString += "\"";
            queryString += note[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (group_location[0].length() > 0) {
        if (andAppend) {
            queryString += ",group_location=";
            queryString += "\"";
            queryString += group_location[0];
            queryString += "\"";
        }
        else {
            queryString += "group_location=";
            queryString += "\"";
            queryString += group_location[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (encrypt[0].length() > 0) {
        if (andAppend) {
            queryString += ",encrypt=";
            queryString += "\"";
            queryString += encrypt[0];
            queryString += "\"";
        }
        else {
            queryString += "encrypt=";
            queryString += "\"";
            queryString += encrypt[0];
            queryString += "\"";
        }
        andAppend = true;
    }

    andAppend = false;

    if (id[1] > 0 || tel[1].length() > 0 || name[1].length() > 0 || cell[1].length() > 0
        || note[1].length() > 0 || group_location[1].length() > 0 || encrypt[1].length() > 0) {
        queryString += " where ";
    }

    if (id[1] > 0) {
        queryString += "id=";
        queryString += QString::number(id[1]);
        andAppend = true;
    }

    if (tel[1].length() > 0) {
        if (andAppend) {
            queryString += " and tel=";
            queryString += "\"";
            queryString += tel[1];
            queryString += "\"";
        }
        else {
            queryString += "tel=";
            queryString += "\"";
            queryString += tel[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name[1].length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (cell[1].length() > 0) {
        if (andAppend) {
            queryString += " and cell=";
            queryString += "\"";
            queryString += cell[1];
            queryString += "\"";
        }
        else {
            queryString += "cell=";
            queryString += "\"";
            queryString += cell[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (note[1].length() > 0) {
        if (andAppend) {
            queryString += " and note=";
            queryString += "\"";
            queryString += note[1];
            queryString += "\"";
        }
        else {
            queryString += "note=";
            queryString += "\"";
            queryString += note[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (group_location[1].length() > 0) {
        if (andAppend) {
            queryString += " and group_location=";
            queryString += "\"";
            queryString += group_location[1];
            queryString += "\"";
        }
        else {
            queryString += "group_location=";
            queryString += "\"";
            queryString += group_location[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    if (encrypt[1].length() > 0) {
        if (andAppend) {
            queryString += " and encrypt=";
            queryString += "\"";
            queryString += encrypt[1];
            queryString += "\"";
        }
        else {
            queryString += "encrypt=";
            queryString += "\"";
            queryString += encrypt[1];
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);

    ret = query.exec();

    if (ret) {
        if (con.cell == cell[0] && con.name == name[0]) {

        }
        else if (con.cell == cell[0] && con.name != name[0]) {
            CSqlDB::Box_UpdateContact(con.cell, name[0]);
        }
        else {
            CSqlDB::Box_UpdateContact(con.cell);
        }

    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

QList<SContact> CSqlDB::Contact_SelectItems(int id, QString tel, QString name, QString cell,
    QString note, QString group_location, QString encrypt)
{
    QList<SContact> list;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("SELECT * FROM contact");

    bool andAppend = false;

    if (id > 0 || tel.length() > 0 || name .length() > 0 || cell.length() > 0 || note.length() > 0
        || group_location.length() > 0 || encrypt.length()) {
        queryString += " where ";
    }

    if (id > 0) {
        queryString += "id=";
        queryString += QString::number(id);
        andAppend = true;
    }

    if (tel.length() > 0) {
        if (andAppend) {
            queryString += " and tel=";
            queryString += "\"";
            queryString += tel;
            queryString += "\"";
        }
        else {
            queryString += "tel=";
            queryString += "\"";
            queryString += tel;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (name.length() > 0) {
        if (andAppend) {
            queryString += " and name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        else {
            queryString += "name=";
            queryString += "\"";
            queryString += name;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (cell.length() > 0) {
        if (andAppend) {
            queryString += " and cell=";
            queryString += "\"";
            queryString += cell;
            queryString += "\"";
        }
        else {
            queryString += "cell=";
            queryString += "\"";
            queryString += cell;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (note.length() > 0) {
        if (andAppend) {
            queryString += " and note=";
            queryString += "\"";
            queryString += note;
            queryString += "\"";
        }
        else {
            queryString += "note=";
            queryString += "\"";
            queryString += note;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (group_location.length() > 0) {
        if (andAppend) {
            queryString += " and group_location=";
            queryString += "\"";
            queryString += group_location;
            queryString += "\"";
        }
        else {
            queryString += "group_location=";
            queryString += "\"";
            queryString += group_location;
            queryString += "\"";
        }
        andAppend = true;
    }

    if (encrypt.length() > 0) {
        if (andAppend) {
            queryString += " and encrypt=";
            queryString += "\"";
            queryString += encrypt;
            queryString += "\"";
        }
        else {
            queryString += "encrypt=";
            queryString += "\"";
            queryString += encrypt;
            queryString += "\"";
        }
        andAppend = true;
    }

    query.prepare(queryString);
    query.exec();

    while (query.next()) {
        int sid = query.value(0).toInt();
        QString stel = query.value(1).toString();
        QString sname = query.value(2).toString();
        QString scell = query.value(3).toString();
        QString snote = query.value(4).toString();
        QString sgroup = query.value(5).toString();
        QString sencrypt = query.value(6).toString();

        SContact contmp;

        contmp.id = sid;
        contmp.name = sname;
        contmp.tel = stel;
        contmp.cell = scell;
        contmp.note = snote;
        contmp.group_location = sgroup;
        contmp.encrypt = sencrypt;

        list.append(contmp);
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    return list;
}

bool CSqlDB::Message_AddItem(SMessage msg)
{
    return CSqlDB::Message_AddItem(msg.mid, msg.type, msg.name, msg.content);
}

bool CSqlDB::Message_DelItem(SMessage msg)
{
    return CSqlDB::Message_DelItem(msg.mid, msg.type, msg.name, msg.content);
}

bool CSqlDB::Message_UpdateItem(SMessage from, SMessage to)
{
    QString strArray[4][2] = { QString() };

    //	strArray[0][0] = QString::number(to.mid);
    //	strArray[0][1] = QString::number(from.mid);
    strArray[1][0] = to.type;
    strArray[1][1] = from.type;
    strArray[2][0] = to.name;
    strArray[2][1] = from.name;
    strArray[3][0] = to.content;
    strArray[3][1] = from.content;

    int ai[2];
    ai[0] = to.mid;
    ai[1] = from.mid;

    return CSqlDB::Message_UpdateItem(ai, strArray[1], strArray[2], strArray[3]);

}

QList<SMessage> CSqlDB::Message_SelectItems(SMessage msg)
{
    return CSqlDB::Message_SelectItems(msg.mid, msg.type, msg.name, msg.content);
}

QList<SGroup> CSqlDB::Group_SelectItems(SGroup msg)
{
    return CSqlDB::Group_SelectItems(msg.mid, msg.type, msg.name);
}

bool CSqlDB::Group_AddItem(SGroup msg)
{
    return CSqlDB::Group_AddItem(msg.mid, msg.type, msg.name);
}

bool CSqlDB::Group_DelItem(SGroup msg)
{
    return CSqlDB::Group_DelItem(msg.mid, msg.type, msg.name);
}

bool CSqlDB::Group_UpdateItem(SGroup from, SGroup to)
{
    QString strArray[3][2] = { QString() };

    //  strArray[0][0] = QString::number(to.mid);
    //  strArray[0][1] = QString::number(from.mid);
    strArray[1][0] = to.type;
    strArray[1][1] = from.type;
    strArray[2][0] = to.name;
    strArray[2][1] = from.name;

    int ai[2];
    ai[0] = to.mid;
    ai[1] = from.mid;

    return CSqlDB::Group_UpdateItem(ai, strArray[1], strArray[2]);

}

QList<SAccount> CSqlDB::Account_SelectItems(SAccount msg)
{
    return CSqlDB::Account_SelectItems(msg.id, msg.id_number, msg.name, msg.acc_number, msg.note);
}

bool CSqlDB::Account_AddItem(SAccount msg)
{
    return CSqlDB::Account_AddItem(msg.id, msg.id_number, msg.name, msg.acc_number, msg.note);
}

bool CSqlDB::Account_DelItem(SAccount msg)
{
    return CSqlDB::Account_DelItem(msg.id, msg.id_number, msg.name, msg.acc_number, msg.note);
}

bool CSqlDB::Account_UpdateItem(SAccount from, SAccount to)
{
    QString strArray[5][2] = { QString() };

    //  strArray[0][0] = QString::number(to.mid);
    //  strArray[0][1] = QString::number(from.mid);
    strArray[1][0] = to.id_number;
    strArray[1][1] = from.id_number;
    strArray[2][0] = to.name;
    strArray[2][1] = from.name;
    strArray[3][0] = to.acc_number;
    strArray[3][1] = from.acc_number;
    strArray[4][0] = to.note;
    strArray[4][1] = from.note;

    int ai[2];
    ai[0] = to.id;
    ai[1] = from.id;

    return CSqlDB::Account_UpdateItem(ai, strArray[1], strArray[2], strArray[3], strArray[4]);

}

bool CSqlDB::Box_AddItem(SBox box)
{
    return CSqlDB::Box_AddItem(box.id, box.sender, box.date_time, box.sign, box.type, box.location,
        box.contact);
}

bool CSqlDB::Box_DelItem(SBox box)
{
    return CSqlDB::Box_DelItem(box.id, box.sender, box.date_time, box.sign, box.type, box.location,
        box.contact);
}

bool CSqlDB::Box_UpdateItem(SBox from, SBox to)
{
    QString strArray[7][2] = { QString() };
    //	strArray[0][0] = QString::number(to.id);
    //	strArray[0][1] = QString::number(from.id);
    strArray[1][0] = to.sender;
    strArray[1][1] = from.sender;
    strArray[2][0] = to.date_time;
    strArray[2][1] = from.date_time;
    strArray[3][0] = to.sign;
    strArray[3][1] = from.sign;
    strArray[4][0] = to.type;
    strArray[4][1] = from.type;
    strArray[5][0] = to.location;
    strArray[5][1] = from.location;
    strArray[6][0] = to.contact;
    strArray[6][1] = from.contact;

    int ia[2];
    ia[0] = to.id;
    ia[1] = from.id;

    return CSqlDB::Box_UpdateItem(ia, strArray[1], strArray[2], strArray[3], strArray[4],
        strArray[5], strArray[6]);
}

QList<SBox> CSqlDB::Box_SelectItems(SBox box)
{
    return CSqlDB::Box_SelectItems(box.id, box.sender, box.date_time, box.sign, box.type,
        box.location, box.contact);
}

bool CSqlDB::Contact_AddItem(SContact contact)
{
    return CSqlDB::Contact_AddItem(contact.id, contact.tel, contact.name, contact.cell,
        contact.note, contact.group_location, contact.encrypt);
}

bool CSqlDB::Contact_DelItem(SContact contact)
{
    return CSqlDB::Contact_DelItem(contact.id, contact.tel, contact.name, contact.cell,
        contact.note, contact.group_location, contact.encrypt);
}

bool CSqlDB::Contact_UpdateItem(SContact from, SContact to)
{
    QString strArray[7][2] = { QString() };
    //	strArray[0][0] = to.id;
    //	strArray[0][1] = from.id;
    strArray[1][0] = to.tel;
    strArray[1][1] = from.tel;
    strArray[2][0] = to.name;
    strArray[2][1] = from.name;
    strArray[3][0] = to.cell;
    strArray[3][1] = from.cell;
    strArray[4][0] = to.note;
    strArray[4][1] = from.note;
    strArray[5][0] = to.group_location;
    strArray[5][1] = from.group_location;
    strArray[6][0] = to.encrypt;
    strArray[6][1] = from.encrypt;

    int ia[2];
    ia[0] = to.id;
    ia[1] = from.id;

    return CSqlDB::Contact_UpdateItem(ia, strArray[1], strArray[2], strArray[3], strArray[4],
        strArray[5], strArray[6]);
}

QList<SContact> CSqlDB::Contact_SelectItems(SContact contact)
{
    return CSqlDB::Contact_SelectItems(contact.id, contact.tel, contact.name, contact.cell,
        contact.note, contact.group_location, contact.encrypt);
}

int CSqlDB::Box_Select_Max_ID()
{
    int ret = 0;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("select * FROM box where id = (select max(id) from box);");

    query.exec();
    //    query.prepare("select max(id) from box;");
    //    
    //    bool b = query.exec();

    while (query.next()) {
        ret = query.value(0).toInt();
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    ret++;

    return ret;
}

int CSqlDB::Contact_Select_Max_ID()
{
    int ret = 0;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("select * FROM contact where id = (select max(id) from contact)");

    query.exec();

    while (query.next()) {
        ret = query.value(0).toInt();
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    ret++;

    return ret;
}

int CSqlDB::Group_Select_Max_ID()
{
    int ret = 0;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("select * FROM contactgroup where id = (select max(id) from contactgroup)");

    query.exec();

    while (query.next()) {
        ret = query.value(0).toInt();
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    ret++;

    return ret;
}

int CSqlDB::EBold_Select_Max_ID()
{
    int ret = 1;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("select max(id) from ebold");

    query.exec();

    while (query.next()) {
        ret = query.value(0).toInt();
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    if (ret == 0) {
        return 2;
    }

    ret++;

    return ret;
}

int CSqlDB::Account_Select_Max_ID()
{
    int ret = 0;

    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    query.prepare("select max(id) from account");

    query.exec();

    while (query.next()) {
        ret = query.value(0).toInt();
    }

    //db.close();
    //db.removeDatabase("QSQLITE");

    ret++;

    return ret;
}

bool CSqlDB::Box_UpdateContact(QString sender, QString nameto)
{
    bool ret = false;
    //QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    //db.setDatabaseName("taiji.db");
    //db.open();

    QSqlQuery query;

    QString queryString = ("update box");

    queryString += " set ";

    queryString += "contact=";
    queryString += "\"";
    queryString += nameto;
    queryString += "\"";

    queryString += " where ";

    queryString += "sender=";
    queryString += "\"";
    queryString += sender;
    queryString += "\"";

    query.prepare(queryString);

    ret = query.exec();

    //db.close();
    //db.removeDatabase("QSQLITE");

    return ret;
}

QList<SEBold> CSqlDB::EBold_SelectItems(SEBold msg)
{
    return CSqlDB::EBold_SelectItems(msg.id, msg.fid, msg.start_id, msg.next_id, msg.name,
        msg.type, msg.title, msg.content, msg.date_time);
}

bool CSqlDB::EBold_AddItem(SEBold msg)
{
    return CSqlDB::EBold_AddItem(msg.id, msg.fid, msg.start_id, msg.next_id, msg.name, msg.type,
        msg.title, msg.content, msg.date_time);
}

bool CSqlDB::EBold_DelItem(SEBold msg)
{
    return CSqlDB::EBold_DelItem(msg.id);
}

bool CSqlDB::EBold_UpdateItem(SEBold from, SEBold to)
{
    QString strArray[9][2] = { QString() };

    //  strArray[0][0] = QString::number(to.mid);
    //  strArray[0][1] = QString::number(from.mid);
    strArray[4][0] = to.name;
    strArray[4][1] = from.name;
    strArray[5][0] = to.type;
    strArray[5][1] = from.type;
    strArray[6][0] = to.title;
    strArray[6][1] = from.title;
    strArray[7][0] = to.content;
    strArray[7][1] = from.content;
    strArray[8][0] = to.date_time;
    strArray[8][1] = from.date_time;

    int ai[4][2];
    ai[0][0] = to.id;
    ai[0][1] = from.id;
    ai[1][0] = to.fid;
    ai[1][1] = from.fid;
    ai[2][0] = to.start_id;
    ai[2][1] = from.start_id;
    ai[3][0] = to.next_id;
    ai[3][1] = from.next_id;

    return CSqlDB::EBold_UpdateItem(ai[0], ai[1], ai[2], ai[3], strArray[4], strArray[5],
        strArray[6], strArray[7], strArray[8]);
}
