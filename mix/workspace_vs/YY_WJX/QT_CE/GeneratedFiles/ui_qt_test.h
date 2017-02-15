/********************************************************************************
** Form generated from reading UI file 'qt_test.ui'
**
** Created: Fri Nov 4 11:02:27 2011
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
#include <QtGui/QHeaderView>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QPushButton>
#include <QtGui/QTextEdit>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_QT_TESTClass
{
public:
    QAction *actionExit;
    QWidget *centralWidget;
    QPushButton *pushButton_INPUT;
    QTextEdit *textEdit;
    QLineEdit *lineEdit;
    QPushButton *pushButton_INPUT_PANEL;

    void setupUi(QMainWindow *QT_TESTClass)
    {
        if (QT_TESTClass->objectName().isEmpty())
            QT_TESTClass->setObjectName(QString::fromUtf8("QT_TESTClass"));
        QT_TESTClass->resize(240, 400);
        actionExit = new QAction(QT_TESTClass);
        actionExit->setObjectName(QString::fromUtf8("actionExit"));
        centralWidget = new QWidget(QT_TESTClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        pushButton_INPUT = new QPushButton(centralWidget);
        pushButton_INPUT->setObjectName(QString::fromUtf8("pushButton_INPUT"));
        pushButton_INPUT->setGeometry(QRect(0, 380, 101, 23));
        textEdit = new QTextEdit(centralWidget);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));
        textEdit->setGeometry(QRect(60, 80, 104, 64));
        lineEdit = new QLineEdit(centralWidget);
        lineEdit->setObjectName(QString::fromUtf8("lineEdit"));
        lineEdit->setGeometry(QRect(60, 180, 113, 20));
        pushButton_INPUT_PANEL = new QPushButton(centralWidget);
        pushButton_INPUT_PANEL->setObjectName(QString::fromUtf8("pushButton_INPUT_PANEL"));
        pushButton_INPUT_PANEL->setGeometry(QRect(140, 380, 101, 23));
        QT_TESTClass->setCentralWidget(centralWidget);

        retranslateUi(QT_TESTClass);
        QObject::connect(actionExit, SIGNAL(triggered()), QT_TESTClass, SLOT(close()));

        QMetaObject::connectSlotsByName(QT_TESTClass);
    } // setupUi

    void retranslateUi(QMainWindow *QT_TESTClass)
    {
        QT_TESTClass->setWindowTitle(QApplication::translate("QT_TESTClass", "QT_TEST", 0, QApplication::UnicodeUTF8));
        actionExit->setText(QApplication::translate("QT_TESTClass", "E&xit", 0, QApplication::UnicodeUTF8));
        pushButton_INPUT->setText(QApplication::translate("QT_TESTClass", "\350\276\223\345\205\245\346\263\225", 0, QApplication::UnicodeUTF8));
        pushButton_INPUT_PANEL->setText(QApplication::translate("QT_TESTClass", "\346\211\223\345\274\200SIP", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class QT_TESTClass: public Ui_QT_TESTClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QT_TEST_H
