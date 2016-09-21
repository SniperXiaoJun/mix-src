#ifndef RANKLISTFORM_H
#define RANKLISTFORM_H

#include <QWidget>
#include<QSqlDatabase>
#include<QSqlQuery>
#include<QDialog>
#include<QMouseEvent>
#include<QDebug>
#include<QVector>

namespace Ui {
    class ranklistForm;
}

class ranklistForm : public QDialog
{
    Q_OBJECT

public:
    explicit ranklistForm(QWidget *parent, bool& opend);
    ~ranklistForm();
    void mousePressEvent(QMouseEvent *);

private:
    Ui::ranklistForm *ui;
    bool &is_opened;
};

#endif // RANKLISTFORM_H
