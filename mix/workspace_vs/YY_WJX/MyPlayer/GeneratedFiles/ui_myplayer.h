/********************************************************************************
** Form generated from reading UI file 'myplayer.ui'
**
** Created: Thu Feb 17 15:15:06 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MYPLAYER_H
#define UI_MYPLAYER_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MyPlayerClass
{
public:
    QAction *actionExit;
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QPushButton *pushButtonAdd;
    QPushButton *pushButtonBack;
    QPushButton *pushButtonPlay;
    QPushButton *pushButtonNext;
    QPushButton *pushButtonDel;
    QWidget *widget;
    QMenuBar *menuBar;
    QMenu *menu_File;

    void setupUi(QMainWindow *MyPlayerClass)
    {
        if (MyPlayerClass->objectName().isEmpty())
            MyPlayerClass->setObjectName(QString::fromUtf8("MyPlayerClass"));
        MyPlayerClass->resize(422, 400);
        actionExit = new QAction(MyPlayerClass);
        actionExit->setObjectName(QString::fromUtf8("actionExit"));
        centralWidget = new QWidget(MyPlayerClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        pushButtonAdd = new QPushButton(centralWidget);
        pushButtonAdd->setObjectName(QString::fromUtf8("pushButtonAdd"));

        gridLayout->addWidget(pushButtonAdd, 0, 0, 1, 1);

        pushButtonBack = new QPushButton(centralWidget);
        pushButtonBack->setObjectName(QString::fromUtf8("pushButtonBack"));

        gridLayout->addWidget(pushButtonBack, 0, 1, 1, 1);

        pushButtonPlay = new QPushButton(centralWidget);
        pushButtonPlay->setObjectName(QString::fromUtf8("pushButtonPlay"));

        gridLayout->addWidget(pushButtonPlay, 0, 2, 1, 1);

        pushButtonNext = new QPushButton(centralWidget);
        pushButtonNext->setObjectName(QString::fromUtf8("pushButtonNext"));

        gridLayout->addWidget(pushButtonNext, 0, 3, 1, 1);

        pushButtonDel = new QPushButton(centralWidget);
        pushButtonDel->setObjectName(QString::fromUtf8("pushButtonDel"));

        gridLayout->addWidget(pushButtonDel, 0, 4, 1, 1);

        widget = new QWidget(centralWidget);
        widget->setObjectName(QString::fromUtf8("widget"));

        gridLayout->addWidget(widget, 1, 0, 1, 5);

        MyPlayerClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(MyPlayerClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 422, 20));
        menu_File = new QMenu(menuBar);
        menu_File->setObjectName(QString::fromUtf8("menu_File"));
        MyPlayerClass->setMenuBar(menuBar);

        menuBar->addAction(menu_File->menuAction());
        menu_File->addAction(actionExit);

        retranslateUi(MyPlayerClass);
        QObject::connect(actionExit, SIGNAL(triggered()), MyPlayerClass, SLOT(close()));

        QMetaObject::connectSlotsByName(MyPlayerClass);
    } // setupUi

    void retranslateUi(QMainWindow *MyPlayerClass)
    {
        MyPlayerClass->setWindowTitle(QApplication::translate("MyPlayerClass", "MyPlayer", 0, QApplication::UnicodeUTF8));
        actionExit->setText(QApplication::translate("MyPlayerClass", "E&xit", 0, QApplication::UnicodeUTF8));
        pushButtonAdd->setText(QApplication::translate("MyPlayerClass", "Add", 0, QApplication::UnicodeUTF8));
        pushButtonBack->setText(QApplication::translate("MyPlayerClass", "Back", 0, QApplication::UnicodeUTF8));
        pushButtonPlay->setText(QApplication::translate("MyPlayerClass", "Play", 0, QApplication::UnicodeUTF8));
        pushButtonNext->setText(QApplication::translate("MyPlayerClass", "Next", 0, QApplication::UnicodeUTF8));
        pushButtonDel->setText(QApplication::translate("MyPlayerClass", "Del", 0, QApplication::UnicodeUTF8));
        menu_File->setTitle(QApplication::translate("MyPlayerClass", "&File", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class MyPlayerClass: public Ui_MyPlayerClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MYPLAYER_H
