#ifndef CINBOXCWIDGET_H
#define CINBOXCWIDGET_H

#include <QtGui/QWidget>
#include "ui_CInboxCWidget.h"

class CInboxCWidget : public QWidget
{
    Q_OBJECT

public:
    CInboxCWidget(QWidget *parent = 0);
    ~CInboxCWidget();

private:
    Ui::CInboxCWidgetClass ui;
};

#endif // CINBOXCWIDGET_H
