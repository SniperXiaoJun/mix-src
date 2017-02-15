/********************************************************************************
** Form generated from reading UI file 'cchgstatus.ui'
**
** Created: Fri May 6 10:57:17 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CCHGSTATUS_H
#define UI_CCHGSTATUS_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QStatusBar>
#include <QtGui/QToolBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CChgStatusClass
{
public:
    QAction *actionExit;
    QAction *action;
    QWidget *centralWidget;
    QMenuBar *menuBar;
    QMenu *menu;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CChgStatusClass)
    {
        if (CChgStatusClass->objectName().isEmpty())
            CChgStatusClass->setObjectName(QString::fromUtf8("CChgStatusClass"));
        CChgStatusClass->resize(229, 289);
        actionExit = new QAction(CChgStatusClass);
        actionExit->setObjectName(QString::fromUtf8("actionExit"));
        action = new QAction(CChgStatusClass);
        action->setObjectName(QString::fromUtf8("action"));
        centralWidget = new QWidget(CChgStatusClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        CChgStatusClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CChgStatusClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 229, 20));
        menu = new QMenu(menuBar);
        menu->setObjectName(QString::fromUtf8("menu"));
        CChgStatusClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CChgStatusClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CChgStatusClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(CChgStatusClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CChgStatusClass->setStatusBar(statusBar);

        menuBar->addAction(menu->menuAction());
        menu->addAction(actionExit);
        menu->addAction(action);

        retranslateUi(CChgStatusClass);
        QObject::connect(actionExit, SIGNAL(triggered()), CChgStatusClass, SLOT(close()));

        QMetaObject::connectSlotsByName(CChgStatusClass);
    } // setupUi

    void retranslateUi(QMainWindow *CChgStatusClass)
    {
        CChgStatusClass->setWindowTitle(QApplication::translate("CChgStatusClass", "CChgStatus", 0, QApplication::UnicodeUTF8));
        actionExit->setText(QApplication::translate("CChgStatusClass", "Exit", 0, QApplication::UnicodeUTF8));
        action->setText(QApplication::translate("CChgStatusClass", "\346\224\271\345\217\230\347\212\266\346\200\201", 0, QApplication::UnicodeUTF8));
        menu->setTitle(QApplication::translate("CChgStatusClass", "\350\217\234\345\215\225", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CChgStatusClass: public Ui_CChgStatusClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CCHGSTATUS_H
