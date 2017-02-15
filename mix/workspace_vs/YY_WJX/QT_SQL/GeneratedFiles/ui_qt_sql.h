/********************************************************************************
** Form generated from reading UI file 'qt_sql.ui'
**
** Created: Mon Nov 7 10:55:17 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QT_SQL_H
#define UI_QT_SQL_H

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

class Ui_QT_SQLClass
{
public:
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QWidget *centralWidget;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *QT_SQLClass)
    {
        if (QT_SQLClass->objectName().isEmpty())
            QT_SQLClass->setObjectName(QString::fromUtf8("QT_SQLClass"));
        QT_SQLClass->resize(600, 400);
        menuBar = new QMenuBar(QT_SQLClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        QT_SQLClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(QT_SQLClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        QT_SQLClass->addToolBar(mainToolBar);
        centralWidget = new QWidget(QT_SQLClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        QT_SQLClass->setCentralWidget(centralWidget);
        statusBar = new QStatusBar(QT_SQLClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        QT_SQLClass->setStatusBar(statusBar);

        retranslateUi(QT_SQLClass);

        QMetaObject::connectSlotsByName(QT_SQLClass);
    } // setupUi

    void retranslateUi(QMainWindow *QT_SQLClass)
    {
        QT_SQLClass->setWindowTitle(QApplication::translate("QT_SQLClass", "QT_SQL", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class QT_SQLClass: public Ui_QT_SQLClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QT_SQL_H
