/********************************************************************************
** Form generated from reading UI file 'CSwitchWindow.ui'
**
** Created: Wed Apr 6 15:04:31 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CSWITCHWINDOW_H
#define UI_CSWITCHWINDOW_H

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

class Ui_CSwitchWindowClass
{
public:
    QWidget *centralWidget;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CSwitchWindowClass)
    {
        if (CSwitchWindowClass->objectName().isEmpty())
            CSwitchWindowClass->setObjectName(QString::fromUtf8("CSwitchWindowClass"));
        CSwitchWindowClass->resize(240, 375);
        centralWidget = new QWidget(CSwitchWindowClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        CSwitchWindowClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CSwitchWindowClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 240, 20));
        CSwitchWindowClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CSwitchWindowClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CSwitchWindowClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(CSwitchWindowClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CSwitchWindowClass->setStatusBar(statusBar);

        retranslateUi(CSwitchWindowClass);

        QMetaObject::connectSlotsByName(CSwitchWindowClass);
    } // setupUi

    void retranslateUi(QMainWindow *CSwitchWindowClass)
    {
        CSwitchWindowClass->setWindowTitle(QApplication::translate("CSwitchWindowClass", "CSwitchWindow", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CSwitchWindowClass: public Ui_CSwitchWindowClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CSWITCHWINDOW_H
