/****************************************************************************
**
** Date    : 2010-07-07
** Author  : furtherchan
** E-Mail  : cnsilan@163.com

** If you have any questions , please contact me
**
****************************************************************************/
#include "mysqlquerymodel.h"
#include <QSqlQuery>

MySqlQueryModel::MySqlQueryModel()
{
}

QVariant MySqlQueryModel::data(const QModelIndex & index, int role) const
{
    QVariant value = QSqlQueryModel::data(index, role);
    if (value.isValid() && role == Qt::DisplayRole && index.column() == 2)
    {
        value = (value.toInt() == 1 ? tr("‘⁄œﬂ") : tr("¿Îœﬂ"));
        return value;
    }

    /*if (value.isValid() && role == Qt::TextColorRole && index.column() == 2)
    {
        return ( value.toInt() == 1 ? qVariantFromValue(QColor(Qt::red))\
            :qVariantFromValue(QColor(Qt::gray)) );
    }
    */

    /*if (role == Qt::TextColorRole && index.column() == 2)
    {
        return qVariantFromValue(QColor(Qt::red));
    }*/


   //return value;

}
