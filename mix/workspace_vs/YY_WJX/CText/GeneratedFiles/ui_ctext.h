/********************************************************************************
** Form generated from reading UI file 'ctext.ui'
**
** Created: Fri Mar 25 15:09:29 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CTEXT_H
#define UI_CTEXT_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QStatusBar>
#include <QtGui/QTextEdit>
#include <QtGui/QToolBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CTextClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QTextEdit *textEdit;
    QPushButton *pushButton;
    QPushButton *pushButton_2;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CTextClass)
    {
        if (CTextClass->objectName().isEmpty())
            CTextClass->setObjectName(QString::fromUtf8("CTextClass"));
        CTextClass->resize(252, 453);
        centralWidget = new QWidget(CTextClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        textEdit = new QTextEdit(centralWidget);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));

        gridLayout->addWidget(textEdit, 1, 0, 1, 1);

        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        gridLayout->addWidget(pushButton, 0, 0, 1, 1);

        pushButton_2 = new QPushButton(centralWidget);
        pushButton_2->setObjectName(QString::fromUtf8("pushButton_2"));

        gridLayout->addWidget(pushButton_2, 2, 0, 1, 1);

        CTextClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CTextClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 252, 20));
        CTextClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CTextClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CTextClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(CTextClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CTextClass->setStatusBar(statusBar);

        retranslateUi(CTextClass);

        QMetaObject::connectSlotsByName(CTextClass);
    } // setupUi

    void retranslateUi(QMainWindow *CTextClass)
    {
        CTextClass->setWindowTitle(QApplication::translate("CTextClass", "MyClass", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("CTextClass", "\346\267\273\345\212\240\345\233\276\347\211\207", 0, QApplication::UnicodeUTF8));
        pushButton_2->setText(QApplication::translate("CTextClass", "\350\256\276\347\275\256\351\242\234\350\211\262", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CTextClass: public Ui_CTextClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CTEXT_H
