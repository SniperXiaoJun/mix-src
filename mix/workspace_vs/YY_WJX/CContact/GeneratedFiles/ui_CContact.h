/********************************************************************************
** Form generated from reading UI file 'CContact.ui'
**
** Created: Wed Jul 6 16:52:34 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CCONTACT_H
#define UI_CCONTACT_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QListWidget>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QStatusBar>
#include <QtGui/QToolBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CContactClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QListWidget *listWidget;
    QLabel *label;
    QLineEdit *lineEdit;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *CContactClass)
    {
        if (CContactClass->objectName().isEmpty())
            CContactClass->setObjectName(QString::fromUtf8("CContactClass"));
        CContactClass->resize(240, 375);
        centralWidget = new QWidget(CContactClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        listWidget = new QListWidget(centralWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        new QListWidgetItem(listWidget);
        listWidget->setObjectName(QString::fromUtf8("listWidget"));

        gridLayout->addWidget(listWidget, 0, 0, 1, 2);

        label = new QLabel(centralWidget);
        label->setObjectName(QString::fromUtf8("label"));

        gridLayout->addWidget(label, 1, 0, 1, 1);

        lineEdit = new QLineEdit(centralWidget);
        lineEdit->setObjectName(QString::fromUtf8("lineEdit"));

        gridLayout->addWidget(lineEdit, 1, 1, 1, 1);

        CContactClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CContactClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 240, 20));
        CContactClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CContactClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CContactClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(CContactClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        CContactClass->setStatusBar(statusBar);

        retranslateUi(CContactClass);

        QMetaObject::connectSlotsByName(CContactClass);
    } // setupUi

    void retranslateUi(QMainWindow *CContactClass)
    {
        CContactClass->setWindowTitle(QApplication::translate("CContactClass", "CContact", 0, QApplication::UnicodeUTF8));

        const bool __sortingEnabled = listWidget->isSortingEnabled();
        listWidget->setSortingEnabled(false);
        QListWidgetItem *___qlistwidgetitem = listWidget->item(0);
        ___qlistwidgetitem->setText(QApplication::translate("CContactClass", "EditMMS", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem1 = listWidget->item(1);
        ___qlistwidgetitem1->setText(QApplication::translate("CContactClass", "ReadMMS", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem2 = listWidget->item(2);
        ___qlistwidgetitem2->setText(QApplication::translate("CContactClass", "Login", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem3 = listWidget->item(3);
        ___qlistwidgetitem3->setText(QApplication::translate("CContactClass", "Configure", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem4 = listWidget->item(4);
        ___qlistwidgetitem4->setText(QApplication::translate("CContactClass", "\347\216\213\344\272\232\347\273\264", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem5 = listWidget->item(5);
        ___qlistwidgetitem5->setText(QApplication::translate("CContactClass", "\346\235\216\345\274\272\345\274\272", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem6 = listWidget->item(6);
        ___qlistwidgetitem6->setText(QApplication::translate("CContactClass", "\344\270\245\346\265\267\346\210\220", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem7 = listWidget->item(7);
        ___qlistwidgetitem7->setText(QApplication::translate("CContactClass", "\345\244\217\344\274\237", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem8 = listWidget->item(8);
        ___qlistwidgetitem8->setText(QApplication::translate("CContactClass", "\350\203\241\344\271\237", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem9 = listWidget->item(9);
        ___qlistwidgetitem9->setText(QApplication::translate("CContactClass", "\345\270\205\351\276\231\346\210\220", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem10 = listWidget->item(10);
        ___qlistwidgetitem10->setText(QApplication::translate("CContactClass", "\345\274\240\346\226\207", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem11 = listWidget->item(11);
        ___qlistwidgetitem11->setText(QApplication::translate("CContactClass", "\351\233\267\344\272\221", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem12 = listWidget->item(12);
        ___qlistwidgetitem12->setText(QApplication::translate("CContactClass", "\346\235\216\345\206\260", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem13 = listWidget->item(13);
        ___qlistwidgetitem13->setText(QApplication::translate("CContactClass", "\345\274\240\347\273\264", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem14 = listWidget->item(14);
        ___qlistwidgetitem14->setText(QApplication::translate("CContactClass", "\345\220\225\345\250\205\350\220\215", 0, QApplication::UnicodeUTF8));
        listWidget->setSortingEnabled(__sortingEnabled);

        label->setText(QApplication::translate("CContactClass", "\346\237\245\346\211\276\357\274\232", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CContactClass: public Ui_CContactClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CCONTACT_H
