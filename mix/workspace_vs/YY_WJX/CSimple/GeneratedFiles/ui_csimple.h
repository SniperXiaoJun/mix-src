/********************************************************************************
** Form generated from reading UI file 'csimple.ui'
**
** Created: Tue Apr 19 14:37:48 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CSIMPLE_H
#define UI_CSIMPLE_H

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

class Ui_CSimpleClass
{
public:
    QAction *actionClose;
    QAction *actionHide;
    QAction *actionShow;
    QAction *actionMm1;
    QAction *actionMm2;
    QAction *actionVisible;
    QWidget *centralWidget;
    QMenuBar *menuBar;
    QMenu *menu;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CSimpleClass)
    {
        if (CSimpleClass->objectName().isEmpty())
            CSimpleClass->setObjectName(QString::fromUtf8("CSimpleClass"));
        CSimpleClass->resize(240, 375);
        actionClose = new QAction(CSimpleClass);
        actionClose->setObjectName(QString::fromUtf8("actionClose"));
        actionHide = new QAction(CSimpleClass);
        actionHide->setObjectName(QString::fromUtf8("actionHide"));
        actionShow = new QAction(CSimpleClass);
        actionShow->setObjectName(QString::fromUtf8("actionShow"));
        actionMm1 = new QAction(CSimpleClass);
        actionMm1->setObjectName(QString::fromUtf8("actionMm1"));
        actionMm2 = new QAction(CSimpleClass);
        actionMm2->setObjectName(QString::fromUtf8("actionMm2"));
        actionVisible = new QAction(CSimpleClass);
        actionVisible->setObjectName(QString::fromUtf8("actionVisible"));
        centralWidget = new QWidget(CSimpleClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        CSimpleClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CSimpleClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 240, 20));
        menu = new QMenu(menuBar);
        menu->setObjectName(QString::fromUtf8("menu"));
        CSimpleClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CSimpleClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CSimpleClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(CSimpleClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CSimpleClass->setStatusBar(statusBar);

        menuBar->addAction(menu->menuAction());
        menu->addAction(actionClose);
        menu->addAction(actionHide);
        menu->addAction(actionShow);
        menu->addAction(actionMm1);
        menu->addAction(actionMm2);
        menu->addAction(actionVisible);

        retranslateUi(CSimpleClass);
        QObject::connect(actionClose, SIGNAL(triggered()), CSimpleClass, SLOT(close()));
        QObject::connect(actionHide, SIGNAL(triggered()), CSimpleClass, SLOT(hide()));
        QObject::connect(actionShow, SIGNAL(triggered()), CSimpleClass, SLOT(showFullScreen()));

        QMetaObject::connectSlotsByName(CSimpleClass);
    } // setupUi

    void retranslateUi(QMainWindow *CSimpleClass)
    {
        CSimpleClass->setWindowTitle(QApplication::translate("CSimpleClass", "CSimple", 0, QApplication::UnicodeUTF8));
        actionClose->setText(QApplication::translate("CSimpleClass", "\345\205\263\351\227\255", 0, QApplication::UnicodeUTF8));
        actionHide->setText(QApplication::translate("CSimpleClass", "\351\232\220\350\227\217", 0, QApplication::UnicodeUTF8));
        actionShow->setText(QApplication::translate("CSimpleClass", "\346\230\276\347\244\272", 0, QApplication::UnicodeUTF8));
        actionMm1->setText(QApplication::translate("CSimpleClass", "mm1", 0, QApplication::UnicodeUTF8));
        actionMm2->setText(QApplication::translate("CSimpleClass", "mm2", 0, QApplication::UnicodeUTF8));
        actionVisible->setText(QApplication::translate("CSimpleClass", "Visible", 0, QApplication::UnicodeUTF8));
        menu->setTitle(QApplication::translate("CSimpleClass", "\350\217\234\345\215\225", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CSimpleClass: public Ui_CSimpleClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CSIMPLE_H
