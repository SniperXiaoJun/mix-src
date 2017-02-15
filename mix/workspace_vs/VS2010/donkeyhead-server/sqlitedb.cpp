/****************************************************************************
**
** Date    : 2010-05-08
** Author  : furtherchan
** E-Mail  : chendaiyuan5566@163.com

** If you have any questions , please contact me
**
****************************************************************************/

#include "sqlitedb.h"

SqliteDB::SqliteDB()
{
}

void SqliteDB::connectDB()
{
    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("chat.db");
    if ( !db.open())
    {
       QMessageBox::critical(NULL, "Connect to db...", "Connect failed.");
    }
}

void SqliteDB::closeDB()
{
    db.close();
}

void SqliteDB::getUserInfo(QString id)
{
    this->connectDB();
    QSqlQuery  query;
    strListUser.clear();
    /*if(!(query.prepare("select id, password, name from user where id = :id")))
    {QMessageBox::critical(NULL, "prepare", "Prepare failed."+id);}
    query.bindValue(":id",id);
    if(!query.first())
    {QMessageBox::critical(NULL, "exec", "No record.");}
    */

    if (!(query.exec("SELECT id, password, name, logstat,ip FROM user")))
    {
        QMessageBox::critical(NULL, "exec", "Exec failed.");
    }

    while (query.next())
    {
        if ( query.value(0).toString() == id )
        {
            strListUser.append(query.value(0).toString());
            strListUser.append(query.value(1).toString());
            strListUser.append(query.value(2).toString());
            //QMessageBox::critical(NULL, "getUserInfo", query.value(2).toString());
            strListUser.append(query.value(3).toString());
            strListUser.append(query.value(4).toString());
        }
    }
    this->closeDB();
}

//stat 0:ÀëÏß, 1:ÔÚÏß
void SqliteDB::updateUserLogStat(QString id, QString stat)
{
    this->connectDB();

    QSqlQuery  query;
    strListUser.clear();

    if(!(query.prepare("UPDATE user SET logstat = :stat WHERE id = :id")))
    {
        QMessageBox::critical(NULL, "prepare", "Prepare failed.");
    }
    query.bindValue(":id",id);
    query.bindValue(":stat",stat);
    if(!query.exec())
    {
        QMessageBox::critical(NULL, "exec", "Exec failed.");
    }

    this->closeDB();
}

void SqliteDB::updateUserIp(QString id, QString ip)
{
    this->connectDB();

    QSqlQuery  query;
    strListUser.clear();

    if(!(query.prepare("UPDATE user SET ip = :ip WHERE id = :id")))
    {
        QMessageBox::critical(NULL, "prepare", "Prepare failed."+id);
    }
    query.bindValue(":id",id);
    query.bindValue(":ip",ip);
    if(!query.exec())
    {
        QMessageBox::critical(NULL, "exec", "Exec failed.");
    }

    this->closeDB();
}

void SqliteDB::updateUser(QString id, QString name, QString password)
{
    this->connectDB();

    QSqlQuery  query;
    strListUser.clear();

    if(!(query.prepare("UPDATE user SET name = :name, password = :password WHERE id = :id")))
    {
        QMessageBox::critical(NULL, "prepare", "Prepare failed."+id);
    }
    query.bindValue(":id",id);
    query.bindValue(":name",name);
    query.bindValue(":password",password);

    if(!query.exec())
    {
        QMessageBox::critical(NULL, "exec", "Exec failed.");
    }

    this->closeDB();
}

void SqliteDB::getUserAllOnline()
{
    this->connectDB();
    QSqlQuery  query;
    strListId.clear();
    strListName.clear();
    if(!(query.prepare("SELECT id, name FROM user WHERE logstat = :logstat order by logstat desc")))
    {
        QMessageBox::critical(NULL, "prepare", "Prepare failed.");
    }
    query.bindValue(":logstat","1");
    if(!query.exec())
    {
        QMessageBox::critical(NULL, "exec", "Exec failed.");
    }
    while (query.next())
    {
            strListId.append(query.value(0).toString());
            strListName.append(query.value(1).toString());
    }
    this->closeDB();

}

int SqliteDB::insertNewUser( QString id, QString password, QString name, QString ip, QString port)
{
    this->connectDB();
    QSqlQuery  query;
    if (!(query.exec("SELECT id FROM user")))
    {
        QMessageBox::critical(NULL, "exec", "Exec failed.");
        return -1;
    }

    //This id already exist
    while (query.next())
    {
        if ( query.value(0).toString() == id )
        {
            return 0;
        }
    }

    query.prepare("INSERT INTO user (id, password, name, ip, port, logstat)" "VALUES (:id, :password, :name, :ip, :port, :logstat)");
    query.bindValue(":id", id);
    query.bindValue(":password", password);
    query.bindValue(":name", name);
    query.bindValue(":ip", ip);
    query.bindValue(":port", port);

    query.bindValue(":logstat", "0");
    query.exec();

    this->closeDB();

    return 1;
}

/*QString SqliteDB::selectPwd( QString id)
{
    this->connectDB();
    QSqlQuery  query;

    query.bindValue(":id", id);
    if (!(query.exec("SELECT  password  FROM user where id = :id")))
    {
        QMessageBox::critical(NULL, "exec", "Exec failed.");
    }
    return query.value(0).toString() ;
}
*/
