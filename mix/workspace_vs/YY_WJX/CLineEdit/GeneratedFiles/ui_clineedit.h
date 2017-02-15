/********************************************************************************
** Form generated from reading UI file 'clineedit.ui'
**
** Created: Mon Mar 28 14:38:08 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CLINEEDIT_H
#define UI_CLINEEDIT_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QStatusBar>
#include <QtGui/QToolBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CLineEditClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QLineEdit *lineEdit;
    QPushButton *pushButton;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CLineEditClass)
    {
        if (CLineEditClass->objectName().isEmpty())
            CLineEditClass->setObjectName(QString::fromUtf8("CLineEditClass"));
        CLineEditClass->resize(236, 188);
        CLineEditClass->setStyleSheet(QString::fromUtf8("background: red; color: white"));
        centralWidget = new QWidget(CLineEditClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        lineEdit = new QLineEdit(centralWidget);
        lineEdit->setObjectName(QString::fromUtf8("lineEdit"));

        gridLayout->addWidget(lineEdit, 0, 1, 1, 1);

        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        gridLayout->addWidget(pushButton, 0, 0, 1, 1);

        CLineEditClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CLineEditClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 236, 20));
        CLineEditClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CLineEditClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CLineEditClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(CLineEditClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CLineEditClass->setStatusBar(statusBar);

        retranslateUi(CLineEditClass);

        QMetaObject::connectSlotsByName(CLineEditClass);
    } // setupUi

    void retranslateUi(QMainWindow *CLineEditClass)
    {
        CLineEditClass->setWindowTitle(QApplication::translate("CLineEditClass", "CLineEdit", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("CLineEditClass", "BUTTON", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CLineEditClass: public Ui_CLineEditClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CLINEEDIT_H
