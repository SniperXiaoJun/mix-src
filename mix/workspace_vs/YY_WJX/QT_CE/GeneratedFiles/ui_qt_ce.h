/********************************************************************************
** Form generated from reading UI file 'qt_ce.ui'
**
** Created: Fri Nov 4 11:02:27 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QT_CE_H
#define UI_QT_CE_H

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

class Ui_QT_CEClass
{
public:
    QAction *actionExit;
    QWidget *centralWidget;
    QMenuBar *menuBar;
    QMenu *menu_File;

    void setupUi(QMainWindow *QT_CEClass)
    {
        if (QT_CEClass->objectName().isEmpty())
            QT_CEClass->setObjectName(QString::fromUtf8("QT_CEClass"));
        QT_CEClass->resize(600, 400);
        actionExit = new QAction(QT_CEClass);
        actionExit->setObjectName(QString::fromUtf8("actionExit"));
        centralWidget = new QWidget(QT_CEClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        QT_CEClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(QT_CEClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menu_File = new QMenu(menuBar);
        menu_File->setObjectName(QString::fromUtf8("menu_File"));
        QT_CEClass->setMenuBar(menuBar);

        menuBar->addAction(menu_File->menuAction());
        menu_File->addAction(actionExit);

        retranslateUi(QT_CEClass);
        QObject::connect(actionExit, SIGNAL(triggered()), QT_CEClass, SLOT(close()));

        QMetaObject::connectSlotsByName(QT_CEClass);
    } // setupUi

    void retranslateUi(QMainWindow *QT_CEClass)
    {
        QT_CEClass->setWindowTitle(QApplication::translate("QT_CEClass", "QT_CE", 0, QApplication::UnicodeUTF8));
        actionExit->setText(QApplication::translate("QT_CEClass", "E&xit", 0, QApplication::UnicodeUTF8));
        menu_File->setTitle(QApplication::translate("QT_CEClass", "&File", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class QT_CEClass: public Ui_QT_CEClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QT_CE_H
