/********************************************************************************
** Form generated from reading UI file 'ckeypress.ui'
**
** Created: Fri Mar 25 14:59:23 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CKEYPRESS_H
#define UI_CKEYPRESS_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QStatusBar>
#include <QtGui/QToolBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CKeyPressClass
{
public:
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QWidget *centralWidget;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CKeyPressClass)
    {
        if (CKeyPressClass->objectName().isEmpty())
            CKeyPressClass->setObjectName(QString::fromUtf8("CKeyPressClass"));
        CKeyPressClass->resize(600, 400);
        menuBar = new QMenuBar(CKeyPressClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        CKeyPressClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CKeyPressClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CKeyPressClass->addToolBar(mainToolBar);
        centralWidget = new QWidget(CKeyPressClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        CKeyPressClass->setCentralWidget(centralWidget);
        statusBar = new QStatusBar(CKeyPressClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CKeyPressClass->setStatusBar(statusBar);

        retranslateUi(CKeyPressClass);

        QMetaObject::connectSlotsByName(CKeyPressClass);
    } // setupUi

    void retranslateUi(QMainWindow *CKeyPressClass)
    {
        CKeyPressClass->setWindowTitle(QApplication::translate("CKeyPressClass", "CKeyPress", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CKeyPressClass: public Ui_CKeyPressClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CKEYPRESS_H
