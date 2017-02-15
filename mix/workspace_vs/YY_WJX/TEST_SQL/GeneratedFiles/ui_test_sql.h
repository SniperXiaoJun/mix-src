/********************************************************************************
** Form generated from reading UI file 'test_sql.ui'
**
** Created: Tue Dec 6 16:13:33 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TEST_SQL_H
#define UI_TEST_SQL_H

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

class Ui_TEST_SQLClass
{
public:
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QWidget *centralWidget;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *TEST_SQLClass)
    {
        if (TEST_SQLClass->objectName().isEmpty())
            TEST_SQLClass->setObjectName(QString::fromUtf8("TEST_SQLClass"));
        TEST_SQLClass->resize(600, 400);
        menuBar = new QMenuBar(TEST_SQLClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        TEST_SQLClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(TEST_SQLClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        TEST_SQLClass->addToolBar(mainToolBar);
        centralWidget = new QWidget(TEST_SQLClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        TEST_SQLClass->setCentralWidget(centralWidget);
        statusBar = new QStatusBar(TEST_SQLClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        TEST_SQLClass->setStatusBar(statusBar);

        retranslateUi(TEST_SQLClass);

        QMetaObject::connectSlotsByName(TEST_SQLClass);
    } // setupUi

    void retranslateUi(QMainWindow *TEST_SQLClass)
    {
        TEST_SQLClass->setWindowTitle(QApplication::translate("TEST_SQLClass", "TEST_SQL", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class TEST_SQLClass: public Ui_TEST_SQLClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TEST_SQL_H
