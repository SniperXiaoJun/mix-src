/********************************************************************************
** Form generated from reading UI file 'cwindownext.ui'
**
** Created: Wed Apr 6 15:04:31 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CWINDOWNEXT_H
#define UI_CWINDOWNEXT_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QStatusBar>
#include <QtGui/QTextEdit>
#include <QtGui/QToolBar>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CWindowNextClass
{
public:
    QWidget *centralWidget;
    QVBoxLayout *verticalLayout;
    QPushButton *pushButton;
    QTextEdit *textEdit;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CWindowNextClass)
    {
        if (CWindowNextClass->objectName().isEmpty())
            CWindowNextClass->setObjectName(QString::fromUtf8("CWindowNextClass"));
        CWindowNextClass->resize(240, 375);
        centralWidget = new QWidget(CWindowNextClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        verticalLayout = new QVBoxLayout(centralWidget);
        verticalLayout->setSpacing(6);
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        verticalLayout->addWidget(pushButton);

        textEdit = new QTextEdit(centralWidget);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));

        verticalLayout->addWidget(textEdit);

        CWindowNextClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CWindowNextClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 240, 20));
        CWindowNextClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CWindowNextClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CWindowNextClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(CWindowNextClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CWindowNextClass->setStatusBar(statusBar);

        retranslateUi(CWindowNextClass);

        QMetaObject::connectSlotsByName(CWindowNextClass);
    } // setupUi

    void retranslateUi(QMainWindow *CWindowNextClass)
    {
        CWindowNextClass->setWindowTitle(QApplication::translate("CWindowNextClass", "CWindowNext", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("CWindowNextClass", "Back", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CWindowNextClass: public Ui_CWindowNextClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CWINDOWNEXT_H
