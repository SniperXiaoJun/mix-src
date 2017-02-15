/********************************************************************************
** Form generated from reading UI file 'qt_test.ui'
**
** Created: Thu Dec 22 14:54:44 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QT_TEST_H
#define UI_QT_TEST_H

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
#include <QtGui/QTextEdit>
#include <QtGui/QToolBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_QT_TestClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QTextEdit *textEdit;
    QLineEdit *lineEdit;
    QPushButton *pushButton;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *QT_TestClass)
    {
        if (QT_TestClass->objectName().isEmpty())
            QT_TestClass->setObjectName(QString::fromUtf8("QT_TestClass"));
        QT_TestClass->resize(414, 400);
        centralWidget = new QWidget(QT_TestClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        textEdit = new QTextEdit(centralWidget);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));

        gridLayout->addWidget(textEdit, 0, 0, 1, 1);

        lineEdit = new QLineEdit(centralWidget);
        lineEdit->setObjectName(QString::fromUtf8("lineEdit"));

        gridLayout->addWidget(lineEdit, 1, 0, 1, 1);

        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        gridLayout->addWidget(pushButton, 2, 0, 1, 1);

        QT_TestClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(QT_TestClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 414, 19));
        QT_TestClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(QT_TestClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        QT_TestClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(QT_TestClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        QT_TestClass->setStatusBar(statusBar);

        retranslateUi(QT_TestClass);

        QMetaObject::connectSlotsByName(QT_TestClass);
    } // setupUi

    void retranslateUi(QMainWindow *QT_TestClass)
    {
        QT_TestClass->setWindowTitle(QApplication::translate("QT_TestClass", "QT_Test", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("QT_TestClass", "PushButton", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class QT_TestClass: public Ui_QT_TestClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QT_TEST_H
