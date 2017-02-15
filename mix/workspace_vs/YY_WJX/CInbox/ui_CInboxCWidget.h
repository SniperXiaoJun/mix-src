/********************************************************************************
** Form generated from reading UI file 'CInboxCWidget.ui'
**
** Created: Wed Jul 6 15:20:19 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CINBOXCWIDGET_H
#define UI_CINBOXCWIDGET_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QListWidget>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CInboxCWidgetClass
{
public:
    QGridLayout *gridLayout;
    QListWidget *listWidget;

    void setupUi(QWidget *CInboxCWidgetClass)
    {
        if (CInboxCWidgetClass->objectName().isEmpty())
            CInboxCWidgetClass->setObjectName(QString::fromUtf8("CInboxCWidgetClass"));
        CInboxCWidgetClass->resize(240, 300);
        gridLayout = new QGridLayout(CInboxCWidgetClass);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        listWidget = new QListWidget(CInboxCWidgetClass);
        listWidget->setObjectName(QString::fromUtf8("listWidget"));

        gridLayout->addWidget(listWidget, 0, 0, 1, 1);


        retranslateUi(CInboxCWidgetClass);

        QMetaObject::connectSlotsByName(CInboxCWidgetClass);
    } // setupUi

    void retranslateUi(QWidget *CInboxCWidgetClass)
    {
        CInboxCWidgetClass->setWindowTitle(QApplication::translate("CInboxCWidgetClass", "CInboxCWidget", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CInboxCWidgetClass: public Ui_CInboxCWidgetClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CINBOXCWIDGET_H
