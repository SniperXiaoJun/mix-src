/********************************************************************************
** Form generated from reading UI file 'MobileSip.ui'
**
** Created: Mon Nov 7 10:48:50 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MOBILESIP_H
#define UI_MOBILESIP_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QPushButton>
#include <QtGui/QTextEdit>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MobileSipClass
{
public:
    QAction *actionExit;
    QWidget *centralWidget;
    QVBoxLayout *verticalLayout;
    QTextEdit *textEdit;
    QLineEdit *lineEdit;
    QPushButton *pushButton_INPUT_PANEL;
    QPushButton *pushButton_INPUT;

    void setupUi(QMainWindow *MobileSipClass)
    {
        if (MobileSipClass->objectName().isEmpty())
            MobileSipClass->setObjectName(QString::fromUtf8("MobileSipClass"));
        MobileSipClass->resize(240, 355);
        actionExit = new QAction(MobileSipClass);
        actionExit->setObjectName(QString::fromUtf8("actionExit"));
        centralWidget = new QWidget(MobileSipClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        verticalLayout = new QVBoxLayout(centralWidget);
        verticalLayout->setSpacing(6);
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        textEdit = new QTextEdit(centralWidget);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));

        verticalLayout->addWidget(textEdit);

        lineEdit = new QLineEdit(centralWidget);
        lineEdit->setObjectName(QString::fromUtf8("lineEdit"));

        verticalLayout->addWidget(lineEdit);

        pushButton_INPUT_PANEL = new QPushButton(centralWidget);
        pushButton_INPUT_PANEL->setObjectName(QString::fromUtf8("pushButton_INPUT_PANEL"));

        verticalLayout->addWidget(pushButton_INPUT_PANEL);

        pushButton_INPUT = new QPushButton(centralWidget);
        pushButton_INPUT->setObjectName(QString::fromUtf8("pushButton_INPUT"));

        verticalLayout->addWidget(pushButton_INPUT);

        MobileSipClass->setCentralWidget(centralWidget);

        retranslateUi(MobileSipClass);
        QObject::connect(actionExit, SIGNAL(triggered()), MobileSipClass, SLOT(close()));

        QMetaObject::connectSlotsByName(MobileSipClass);
    } // setupUi

    void retranslateUi(QMainWindow *MobileSipClass)
    {
        MobileSipClass->setWindowTitle(QApplication::translate("MobileSipClass", "QT_TEST", 0, QApplication::UnicodeUTF8));
        actionExit->setText(QApplication::translate("MobileSipClass", "E&xit", 0, QApplication::UnicodeUTF8));
        pushButton_INPUT_PANEL->setText(QApplication::translate("MobileSipClass", "\346\211\223\345\274\200SIP", 0, QApplication::UnicodeUTF8));
        pushButton_INPUT->setText(QApplication::translate("MobileSipClass", "\350\276\223\345\205\245\346\263\225", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class MobileSipClass: public Ui_MobileSipClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MOBILESIP_H
