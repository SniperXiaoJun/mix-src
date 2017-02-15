/********************************************************************************
** Form generated from reading UI file 'wince_udp.ui'
**
** Created: Wed Dec 21 17:52:50 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_WINCE_UDP_H
#define UI_WINCE_UDP_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_WinCE_UDPClass
{
public:
    QAction *actionExit;
    QWidget *centralWidget;
    QMenuBar *menuBar;
    QMenu *menu_File;

    void setupUi(QMainWindow *WinCE_UDPClass)
    {
        if (WinCE_UDPClass->objectName().isEmpty())
            WinCE_UDPClass->setObjectName(QString::fromUtf8("WinCE_UDPClass"));
        WinCE_UDPClass->resize(600, 400);
        actionExit = new QAction(WinCE_UDPClass);
        actionExit->setObjectName(QString::fromUtf8("actionExit"));
        centralWidget = new QWidget(WinCE_UDPClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        WinCE_UDPClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(WinCE_UDPClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menu_File = new QMenu(menuBar);
        menu_File->setObjectName(QString::fromUtf8("menu_File"));
        WinCE_UDPClass->setMenuBar(menuBar);

        menuBar->addAction(menu_File->menuAction());
        menu_File->addAction(actionExit);

        retranslateUi(WinCE_UDPClass);
        QObject::connect(actionExit, SIGNAL(triggered()), WinCE_UDPClass, SLOT(close()));

        QMetaObject::connectSlotsByName(WinCE_UDPClass);
    } // setupUi

    void retranslateUi(QMainWindow *WinCE_UDPClass)
    {
        WinCE_UDPClass->setWindowTitle(QApplication::translate("WinCE_UDPClass", "WinCE_UDP", 0, QApplication::UnicodeUTF8));
        actionExit->setText(QApplication::translate("WinCE_UDPClass", "E&xit", 0, QApplication::UnicodeUTF8));
        menu_File->setTitle(QApplication::translate("WinCE_UDPClass", "&File", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class WinCE_UDPClass: public Ui_WinCE_UDPClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_WINCE_UDP_H
