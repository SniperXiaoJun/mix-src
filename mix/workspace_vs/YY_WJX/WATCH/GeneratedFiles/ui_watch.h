/********************************************************************************
** Form generated from reading UI file 'watch.ui'
**
** Created: Thu Feb 24 17:16:10 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_WATCH_H
#define UI_WATCH_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QStatusBar>
#include <QtGui/QToolBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_WATCHClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *WATCHClass)
    {
        if (WATCHClass->objectName().isEmpty())
            WATCHClass->setObjectName(QString::fromUtf8("WATCHClass"));
        WATCHClass->resize(400, 400);
        centralWidget = new QWidget(WATCHClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        WATCHClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(WATCHClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 400, 20));
        WATCHClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(WATCHClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        WATCHClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(WATCHClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        WATCHClass->setStatusBar(statusBar);

        retranslateUi(WATCHClass);

        QMetaObject::connectSlotsByName(WATCHClass);
    } // setupUi

    void retranslateUi(QMainWindow *WATCHClass)
    {
        WATCHClass->setWindowTitle(QApplication::translate("WATCHClass", "WATCH", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class WATCHClass: public Ui_WATCHClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_WATCH_H
