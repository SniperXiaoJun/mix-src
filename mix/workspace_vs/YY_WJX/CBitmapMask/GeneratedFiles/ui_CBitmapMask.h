/********************************************************************************
** Form generated from reading UI file 'CBitmapMask.ui'
**
** Created: Tue May 10 10:27:24 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CBITMAPMASK_H
#define UI_CBITMAPMASK_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CBitmapMaskClass
{
public:
    QWidget *centralWidget;
    QVBoxLayout *verticalLayout;
    QPushButton *pushButton;
    QMenuBar *menuBar;

    void setupUi(QMainWindow *CBitmapMaskClass)
    {
        if (CBitmapMaskClass->objectName().isEmpty())
            CBitmapMaskClass->setObjectName(QString::fromUtf8("CBitmapMaskClass"));
        CBitmapMaskClass->resize(241, 358);
        CBitmapMaskClass->setStyleSheet(QString::fromUtf8(" background-color: rgb(50,50,50);"));
        centralWidget = new QWidget(CBitmapMaskClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        verticalLayout = new QVBoxLayout(centralWidget);
        verticalLayout->setSpacing(6);
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        verticalLayout->addWidget(pushButton);

        CBitmapMaskClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CBitmapMaskClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 241, 20));
        CBitmapMaskClass->setMenuBar(menuBar);

        retranslateUi(CBitmapMaskClass);

        QMetaObject::connectSlotsByName(CBitmapMaskClass);
    } // setupUi

    void retranslateUi(QMainWindow *CBitmapMaskClass)
    {
        CBitmapMaskClass->setWindowTitle(QApplication::translate("CBitmapMaskClass", "CBitmapMask", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("CBitmapMaskClass", "\346\211\223\345\274\200", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CBitmapMaskClass: public Ui_CBitmapMaskClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CBITMAPMASK_H
