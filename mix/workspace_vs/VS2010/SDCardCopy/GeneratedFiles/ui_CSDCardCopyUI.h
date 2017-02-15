/********************************************************************************
** Form generated from reading UI file 'CSDCardCopyUI.ui'
**
** Created: Wed Jun 27 14:58:36 2012
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CSDCARDCOPYUI_H
#define UI_CSDCARDCOPYUI_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QProgressBar>
#include <QtGui/QPushButton>
#include <QtGui/QStatusBar>
#include <QtGui/QToolBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CSDCardCopyUIClass
{
public:
    QAction *action_Setup;
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QPushButton *pushButton_OK;
    QPushButton *pushButton_Cancel;
    QProgressBar *progressBar;
    QLabel *label;
    QMenuBar *menuBar;
    QMenu *menu;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CSDCardCopyUIClass)
    {
        if (CSDCardCopyUIClass->objectName().isEmpty())
            CSDCardCopyUIClass->setObjectName(QString::fromUtf8("CSDCardCopyUIClass"));
        CSDCardCopyUIClass->resize(750, 150);
        CSDCardCopyUIClass->setMinimumSize(QSize(750, 150));
        CSDCardCopyUIClass->setMaximumSize(QSize(750, 150));
        action_Setup = new QAction(CSDCardCopyUIClass);
        action_Setup->setObjectName(QString::fromUtf8("action_Setup"));
        centralWidget = new QWidget(CSDCardCopyUIClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        pushButton_OK = new QPushButton(centralWidget);
        pushButton_OK->setObjectName(QString::fromUtf8("pushButton_OK"));

        gridLayout->addWidget(pushButton_OK, 3, 0, 1, 1);

        pushButton_Cancel = new QPushButton(centralWidget);
        pushButton_Cancel->setObjectName(QString::fromUtf8("pushButton_Cancel"));

        gridLayout->addWidget(pushButton_Cancel, 3, 1, 1, 1);

        progressBar = new QProgressBar(centralWidget);
        progressBar->setObjectName(QString::fromUtf8("progressBar"));
        progressBar->setValue(24);

        gridLayout->addWidget(progressBar, 2, 0, 1, 2);

        label = new QLabel(centralWidget);
        label->setObjectName(QString::fromUtf8("label"));

        gridLayout->addWidget(label, 1, 0, 1, 2);

        CSDCardCopyUIClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CSDCardCopyUIClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 750, 23));
        menu = new QMenu(menuBar);
        menu->setObjectName(QString::fromUtf8("menu"));
        CSDCardCopyUIClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CSDCardCopyUIClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CSDCardCopyUIClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(CSDCardCopyUIClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CSDCardCopyUIClass->setStatusBar(statusBar);

        menuBar->addAction(menu->menuAction());
        menu->addAction(action_Setup);

        retranslateUi(CSDCardCopyUIClass);

        QMetaObject::connectSlotsByName(CSDCardCopyUIClass);
    } // setupUi

    void retranslateUi(QMainWindow *CSDCardCopyUIClass)
    {
        CSDCardCopyUIClass->setWindowTitle(QApplication::translate("CSDCardCopyUIClass", "SDCardCopy", 0, QApplication::UnicodeUTF8));
        action_Setup->setText(QApplication::translate("CSDCardCopyUIClass", "\350\256\276\347\275\256", 0, QApplication::UnicodeUTF8));
        pushButton_OK->setText(QApplication::translate("CSDCardCopyUIClass", "\345\274\200\345\247\213\346\213\267\350\264\235", 0, QApplication::UnicodeUTF8));
        pushButton_Cancel->setText(QApplication::translate("CSDCardCopyUIClass", "\345\217\226\346\266\210\346\213\267\350\264\235", 0, QApplication::UnicodeUTF8));
        label->setText(QString());
        menu->setTitle(QApplication::translate("CSDCardCopyUIClass", "\350\217\234\345\215\225", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CSDCardCopyUIClass: public Ui_CSDCardCopyUIClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CSDCARDCOPYUI_H
