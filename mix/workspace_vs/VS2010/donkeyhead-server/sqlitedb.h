/****************************************************************************
**
** Date    : 2010-07-07
** Author  : furtherchan
** E-Mail  : cnsilan@163.com

** If you have any questions , please contact me
**
****************************************************************************/

#ifndef SQLITEDB_H
#define SQLITEDB_H

#include <QObject>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlQueryModel>
#include <QMessageBox>
#include <QString>
#include <QStringList>

class SqliteDB : public QObject
{

public:
    SqliteDB();
    //member
    QStringList strListUser;

    QStringList strListId;
    QStringList strListName;

    //member function
    void connectDB();
    void closeDB();
    void getUserInfo( QString id );
    void updateUserLogStat( QString id, QString stat );
    int insertNewUser( QString id, QString password, QString name, QString ip, QString port);
    void getUserAllOnline();

    void updateUserIp(QString id, QString ip);
    void updateUser(QString id, QString name, QString password);


private:
    //member
    QSqlDatabase db;

};

#endif // SQLITEDB_H
