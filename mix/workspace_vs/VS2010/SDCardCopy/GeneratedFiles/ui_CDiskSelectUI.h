/********************************************************************************
** Form generated from reading UI file 'CDiskSelectUI.ui'
**
** Created: Wed Jun 27 14:58:36 2012
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CDISKSELECTUI_H
#define UI_CDISKSELECTUI_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QComboBox>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QPushButton>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CDiskSelectUIClass
{
public:
    QGridLayout *gridLayout;
    QPushButton *pushButton_Old;
    QPushButton *pushButton_New;
    QComboBox *comboBox_Old;
    QComboBox *comboBox_New;
    QLabel *label_Old;
    QLabel *label_New;

    void setupUi(QWidget *CDiskSelectUIClass)
    {
        if (CDiskSelectUIClass->objectName().isEmpty())
            CDiskSelectUIClass->setObjectName(QString::fromUtf8("CDiskSelectUIClass"));
        CDiskSelectUIClass->resize(400, 307);
        gridLayout = new QGridLayout(CDiskSelectUIClass);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        pushButton_Old = new QPushButton(CDiskSelectUIClass);
        pushButton_Old->setObjectName(QString::fromUtf8("pushButton_Old"));

        gridLayout->addWidget(pushButton_Old, 0, 0, 1, 1);

        pushButton_New = new QPushButton(CDiskSelectUIClass);
        pushButton_New->setObjectName(QString::fromUtf8("pushButton_New"));

        gridLayout->addWidget(pushButton_New, 0, 1, 1, 1);

        comboBox_Old = new QComboBox(CDiskSelectUIClass);
        comboBox_Old->setObjectName(QString::fromUtf8("comboBox_Old"));

        gridLayout->addWidget(comboBox_Old, 2, 0, 1, 1);

        comboBox_New = new QComboBox(CDiskSelectUIClass);
        comboBox_New->setObjectName(QString::fromUtf8("comboBox_New"));

        gridLayout->addWidget(comboBox_New, 2, 1, 1, 1);

        label_Old = new QLabel(CDiskSelectUIClass);
        label_Old->setObjectName(QString::fromUtf8("label_Old"));

        gridLayout->addWidget(label_Old, 3, 0, 1, 1);

        label_New = new QLabel(CDiskSelectUIClass);
        label_New->setObjectName(QString::fromUtf8("label_New"));

        gridLayout->addWidget(label_New, 3, 1, 1, 1);


        retranslateUi(CDiskSelectUIClass);

        QMetaObject::connectSlotsByName(CDiskSelectUIClass);
    } // setupUi

    void retranslateUi(QWidget *CDiskSelectUIClass)
    {
        CDiskSelectUIClass->setWindowTitle(QApplication::translate("CDiskSelectUIClass", "CDiskSelectUI", 0, QApplication::UnicodeUTF8));
        pushButton_Old->setText(QApplication::translate("CDiskSelectUIClass", "\347\273\221\345\256\232\345\216\237SD\345\215\241", 0, QApplication::UnicodeUTF8));
        pushButton_New->setText(QApplication::translate("CDiskSelectUIClass", "\347\273\221\345\256\232\346\226\260SD\345\215\241", 0, QApplication::UnicodeUTF8));
        label_Old->setText(QApplication::translate("CDiskSelectUIClass", "\345\216\237\345\215\241:", 0, QApplication::UnicodeUTF8));
        label_New->setText(QApplication::translate("CDiskSelectUIClass", "\346\226\260\345\215\241:", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CDiskSelectUIClass: public Ui_CDiskSelectUIClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CDISKSELECTUI_H
