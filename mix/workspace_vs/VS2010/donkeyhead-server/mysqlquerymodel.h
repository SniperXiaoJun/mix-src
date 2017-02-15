/****************************************************************************
**
** Date    : 2010-07-07
** Author  : furtherchan
** E-Mail  : cnsilan@163.com

** If you have any questions , please contact me
**
****************************************************************************/

#ifndef MYSQLQUERYMODEL_H
#define MYSQLQUERYMODEL_H

#include <QSqlQueryModel>

class MySqlQueryModel : public QSqlQueryModel
{
    public:
        MySqlQueryModel();

        //implementation virtual function
        QVariant data(const QModelIndex &item, int role=Qt::DisplayRole) const;

};

#endif // MYSQLQUERYMODEL_H
