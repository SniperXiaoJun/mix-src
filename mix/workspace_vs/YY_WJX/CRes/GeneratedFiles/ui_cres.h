/********************************************************************************
** Form generated from reading UI file 'cres.ui'
**
** Created: Fri May 6 16:22:50 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CRES_H
#define UI_CRES_H

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

class Ui_CResClass
{
public:
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QWidget *centralWidget;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CResClass)
    {
        if (CResClass->objectName().isEmpty())
            CResClass->setObjectName(QString::fromUtf8("CResClass"));
        CResClass->resize(600, 400);
        menuBar = new QMenuBar(CResClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        CResClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CResClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CResClass->addToolBar(mainToolBar);
        centralWidget = new QWidget(CResClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        CResClass->setCentralWidget(centralWidget);
        statusBar = new QStatusBar(CResClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CResClass->setStatusBar(statusBar);

        retranslateUi(CResClass);

        QMetaObject::connectSlotsByName(CResClass);
    } // setupUi

    void retranslateUi(QMainWindow *CResClass)
    {
        CResClass->setWindowTitle(QApplication::translate("CResClass", "CRes", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CResClass: public Ui_CResClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CRES_H
