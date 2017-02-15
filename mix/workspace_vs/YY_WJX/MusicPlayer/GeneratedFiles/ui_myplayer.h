/********************************************************************************
** Form generated from reading UI file 'myplayer.ui'
**
** Created: Thu Apr 7 18:20:44 2011
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
#include <QtGui/QListWidget>
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
    QListWidget *listWidget;
    QMenuBar *menuBar;
    QMenu *menu_File;

    void setupUi(QMainWindow *MyPlayerClass)
    {
        if (MyPlayerClass->objectName().isEmpty())
            MyPlayerClass->setObjectName(QString::fromUtf8("MyPlayerClass"));
        MyPlayerClass->resize(417, 400);
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
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/MusicPlayer/Resources/openfile.png"), QSize(), QIcon::Normal, QIcon::Off);
        pushButtonAdd->setIcon(icon);

        gridLayout->addWidget(pushButtonAdd, 0, 0, 1, 1);

        pushButtonBack = new QPushButton(centralWidget);
        pushButtonBack->setObjectName(QString::fromUtf8("pushButtonBack"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/MusicPlayer/Resources/backward.png"), QSize(), QIcon::Normal, QIcon::Off);
        pushButtonBack->setIcon(icon1);

        gridLayout->addWidget(pushButtonBack, 0, 1, 1, 1);

        pushButtonPlay = new QPushButton(centralWidget);
        pushButtonPlay->setObjectName(QString::fromUtf8("pushButtonPlay"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/MusicPlayer/Resources/play.png"), QSize(), QIcon::Normal, QIcon::Off);
        pushButtonPlay->setIcon(icon2);

        gridLayout->addWidget(pushButtonPlay, 0, 2, 1, 1);

        pushButtonNext = new QPushButton(centralWidget);
        pushButtonNext->setObjectName(QString::fromUtf8("pushButtonNext"));
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/MusicPlayer/Resources/step.png"), QSize(), QIcon::Normal, QIcon::Off);
        pushButtonNext->setIcon(icon3);

        gridLayout->addWidget(pushButtonNext, 0, 3, 1, 1);

        pushButtonDel = new QPushButton(centralWidget);
        pushButtonDel->setObjectName(QString::fromUtf8("pushButtonDel"));
        QIcon icon4;
        icon4.addFile(QString::fromUtf8(":/MusicPlayer/Resources/mute.png"), QSize(), QIcon::Normal, QIcon::Off);
        pushButtonDel->setIcon(icon4);

        gridLayout->addWidget(pushButtonDel, 0, 4, 1, 1);

        widget = new QWidget(centralWidget);
        widget->setObjectName(QString::fromUtf8("widget"));

        gridLayout->addWidget(widget, 1, 0, 1, 4);

        listWidget = new QListWidget(centralWidget);
        listWidget->setObjectName(QString::fromUtf8("listWidget"));

        gridLayout->addWidget(listWidget, 1, 4, 1, 1);

        MyPlayerClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(MyPlayerClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 417, 20));
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
        actionExit->setText(QApplication::translate("MyPlayerClass", "\351\200\200\345\207\272", 0, QApplication::UnicodeUTF8));
        pushButtonAdd->setText(QApplication::translate("MyPlayerClass", "\346\211\223\345\274\200", 0, QApplication::UnicodeUTF8));
        pushButtonBack->setText(QApplication::translate("MyPlayerClass", "\344\270\212\344\270\200\344\270\252", 0, QApplication::UnicodeUTF8));
        pushButtonPlay->setText(QApplication::translate("MyPlayerClass", "\346\222\255\346\224\276", 0, QApplication::UnicodeUTF8));
        pushButtonNext->setText(QApplication::translate("MyPlayerClass", "\344\270\213\344\270\200\344\270\252", 0, QApplication::UnicodeUTF8));
        pushButtonDel->setText(QApplication::translate("MyPlayerClass", "\345\210\240\351\231\244", 0, QApplication::UnicodeUTF8));
        menu_File->setTitle(QApplication::translate("MyPlayerClass", "\350\217\234\345\215\225", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class MyPlayerClass: public Ui_MyPlayerClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MYPLAYER_H
