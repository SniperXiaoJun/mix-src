/********************************************************************************
** Form generated from reading UI file 'cwindowback.ui'
**
** Created: Wed Apr 6 15:04:31 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CWINDOWBACK_H
#define UI_CWINDOWBACK_H

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

class Ui_CWindowBackClass
{
public:
    QWidget *centralWidget;
    QVBoxLayout *verticalLayout;
    QPushButton *pushButton;
    QTextEdit *textEdit;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CWindowBackClass)
    {
        if (CWindowBackClass->objectName().isEmpty())
            CWindowBackClass->setObjectName(QString::fromUtf8("CWindowBackClass"));
        CWindowBackClass->resize(240, 375);
        centralWidget = new QWidget(CWindowBackClass);
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

        CWindowBackClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CWindowBackClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 240, 20));
        CWindowBackClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CWindowBackClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CWindowBackClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(CWindowBackClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CWindowBackClass->setStatusBar(statusBar);

        retranslateUi(CWindowBackClass);

        QMetaObject::connectSlotsByName(CWindowBackClass);
    } // setupUi

    void retranslateUi(QMainWindow *CWindowBackClass)
    {
        CWindowBackClass->setWindowTitle(QApplication::translate("CWindowBackClass", "CWindowBack", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("CWindowBackClass", "Next", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CWindowBackClass: public Ui_CWindowBackClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CWINDOWBACK_H
