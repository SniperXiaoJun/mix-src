/********************************************************************************
** Form generated from reading UI file 'CContactUI.ui'
**
** Created: Wed Jul 20 15:38:58 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CCONTACTUI_H
#define UI_CCONTACTUI_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QListWidget>
#include <QtGui/QMainWindow>
#include <QtGui/QPushButton>
#include <QtGui/QTabWidget>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CContactUIClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QTabWidget *tabWidget;
    QWidget *tabE;
    QGridLayout *gridLayout_2;
    QListWidget *listWidgetE;
    QWidget *tabE_GRP;
    QGridLayout *gridLayout_3;
    QListWidget *listWidgetE_GRP;
    QWidget *tab;
    QGridLayout *gridLayout_4;
    QListWidget *listWidget;
    QWidget *tabGRP;
    QGridLayout *gridLayout_5;
    QListWidget *listWidgetGRP;
    QPushButton *pushButton;

    void setupUi(QMainWindow *CContactUIClass)
    {
        if (CContactUIClass->objectName().isEmpty())
            CContactUIClass->setObjectName(QString::fromUtf8("CContactUIClass"));
        CContactUIClass->resize(270, 400);
        CContactUIClass->setStyleSheet(QString::fromUtf8("background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(255, 0, 0, 255), stop:0.166 rgba(255, 255, 0, 255), stop:0.333 rgba(0, 255, 0, 255), stop:0.5 rgba(0, 255, 255, 255), stop:0.666 rgba(0, 0, 255, 255), stop:0.833 rgba(255, 0, 255, 255), stop:1 rgba(255, 0, 0, 255))"));
        centralWidget = new QWidget(CContactUIClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        tabWidget = new QTabWidget(centralWidget);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        tabWidget->setStyleSheet(QString::fromUtf8(""));
        tabE = new QWidget();
        tabE->setObjectName(QString::fromUtf8("tabE"));
        gridLayout_2 = new QGridLayout(tabE);
        gridLayout_2->setSpacing(6);
        gridLayout_2->setContentsMargins(11, 11, 11, 11);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        listWidgetE = new QListWidget(tabE);
        new QListWidgetItem(listWidgetE);
        new QListWidgetItem(listWidgetE);
        listWidgetE->setObjectName(QString::fromUtf8("listWidgetE"));

        gridLayout_2->addWidget(listWidgetE, 0, 0, 1, 1);

        tabWidget->addTab(tabE, QString());
        tabE_GRP = new QWidget();
        tabE_GRP->setObjectName(QString::fromUtf8("tabE_GRP"));
        gridLayout_3 = new QGridLayout(tabE_GRP);
        gridLayout_3->setSpacing(6);
        gridLayout_3->setContentsMargins(11, 11, 11, 11);
        gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));
        listWidgetE_GRP = new QListWidget(tabE_GRP);
        new QListWidgetItem(listWidgetE_GRP);
        new QListWidgetItem(listWidgetE_GRP);
        listWidgetE_GRP->setObjectName(QString::fromUtf8("listWidgetE_GRP"));

        gridLayout_3->addWidget(listWidgetE_GRP, 0, 0, 1, 1);

        tabWidget->addTab(tabE_GRP, QString());
        tab = new QWidget();
        tab->setObjectName(QString::fromUtf8("tab"));
        gridLayout_4 = new QGridLayout(tab);
        gridLayout_4->setSpacing(6);
        gridLayout_4->setContentsMargins(11, 11, 11, 11);
        gridLayout_4->setObjectName(QString::fromUtf8("gridLayout_4"));
        listWidget = new QListWidget(tab);
        listWidget->setObjectName(QString::fromUtf8("listWidget"));

        gridLayout_4->addWidget(listWidget, 0, 0, 1, 1);

        tabWidget->addTab(tab, QString());
        tabGRP = new QWidget();
        tabGRP->setObjectName(QString::fromUtf8("tabGRP"));
        gridLayout_5 = new QGridLayout(tabGRP);
        gridLayout_5->setSpacing(6);
        gridLayout_5->setContentsMargins(11, 11, 11, 11);
        gridLayout_5->setObjectName(QString::fromUtf8("gridLayout_5"));
        listWidgetGRP = new QListWidget(tabGRP);
        listWidgetGRP->setObjectName(QString::fromUtf8("listWidgetGRP"));

        gridLayout_5->addWidget(listWidgetGRP, 0, 0, 1, 1);

        tabWidget->addTab(tabGRP, QString());

        gridLayout->addWidget(tabWidget, 0, 0, 1, 1);

        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        gridLayout->addWidget(pushButton, 1, 0, 1, 1);

        CContactUIClass->setCentralWidget(centralWidget);

        retranslateUi(CContactUIClass);

        tabWidget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(CContactUIClass);
    } // setupUi

    void retranslateUi(QMainWindow *CContactUIClass)
    {
        CContactUIClass->setWindowTitle(QApplication::translate("CContactUIClass", "CContactUI", 0, QApplication::UnicodeUTF8));

        const bool __sortingEnabled = listWidgetE->isSortingEnabled();
        listWidgetE->setSortingEnabled(false);
        QListWidgetItem *___qlistwidgetitem = listWidgetE->item(0);
        ___qlistwidgetitem->setText(QApplication::translate("CContactUIClass", "1", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem1 = listWidgetE->item(1);
        ___qlistwidgetitem1->setText(QApplication::translate("CContactUIClass", "2", 0, QApplication::UnicodeUTF8));
        listWidgetE->setSortingEnabled(__sortingEnabled);

        tabWidget->setTabText(tabWidget->indexOf(tabE), QApplication::translate("CContactUIClass", "\345\212\240\345\257\206\344\272\272", 0, QApplication::UnicodeUTF8));

        const bool __sortingEnabled1 = listWidgetE_GRP->isSortingEnabled();
        listWidgetE_GRP->setSortingEnabled(false);
        QListWidgetItem *___qlistwidgetitem2 = listWidgetE_GRP->item(0);
        ___qlistwidgetitem2->setText(QApplication::translate("CContactUIClass", "11", 0, QApplication::UnicodeUTF8));
        QListWidgetItem *___qlistwidgetitem3 = listWidgetE_GRP->item(1);
        ___qlistwidgetitem3->setText(QApplication::translate("CContactUIClass", "22", 0, QApplication::UnicodeUTF8));
        listWidgetE_GRP->setSortingEnabled(__sortingEnabled1);

        tabWidget->setTabText(tabWidget->indexOf(tabE_GRP), QApplication::translate("CContactUIClass", "\345\212\240\345\257\206\347\273\204", 0, QApplication::UnicodeUTF8));
        tabWidget->setTabText(tabWidget->indexOf(tab), QApplication::translate("CContactUIClass", "\351\235\236\345\257\206\344\272\272", 0, QApplication::UnicodeUTF8));
        tabWidget->setTabText(tabWidget->indexOf(tabGRP), QApplication::translate("CContactUIClass", "\351\235\236\345\257\206\347\273\204", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("CContactUIClass", "PushButton", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CContactUIClass: public Ui_CContactUIClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CCONTACTUI_H
