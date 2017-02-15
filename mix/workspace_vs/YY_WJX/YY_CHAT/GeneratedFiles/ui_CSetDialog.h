/********************************************************************************
** Form generated from reading UI file 'CSetDialog.ui'
**
** Created: Fri Dec 2 15:06:58 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CSETDIALOG_H
#define UI_CSETDIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QPushButton>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CSetDialogClass
{
public:
    QWidget *centralWidget;
    QPushButton *pushButton_OK;
    QPushButton *pushButton_Cancel;
    QLineEdit *lineEdit_Name;
    QLineEdit *lineEdit_Note;
    QLabel *label;
    QLabel *label_2;

    void setupUi(QMainWindow *CSetDialogClass)
    {
        if (CSetDialogClass->objectName().isEmpty())
            CSetDialogClass->setObjectName(QString::fromUtf8("CSetDialogClass"));
        CSetDialogClass->resize(200, 125);
        centralWidget = new QWidget(CSetDialogClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        pushButton_OK = new QPushButton(centralWidget);
        pushButton_OK->setObjectName(QString::fromUtf8("pushButton_OK"));
        pushButton_OK->setGeometry(QRect(10, 90, 75, 23));
        pushButton_Cancel = new QPushButton(centralWidget);
        pushButton_Cancel->setObjectName(QString::fromUtf8("pushButton_Cancel"));
        pushButton_Cancel->setGeometry(QRect(100, 90, 75, 23));
        lineEdit_Name = new QLineEdit(centralWidget);
        lineEdit_Name->setObjectName(QString::fromUtf8("lineEdit_Name"));
        lineEdit_Name->setGeometry(QRect(50, 20, 133, 20));
        lineEdit_Note = new QLineEdit(centralWidget);
        lineEdit_Note->setObjectName(QString::fromUtf8("lineEdit_Note"));
        lineEdit_Note->setGeometry(QRect(50, 50, 133, 20));
        label = new QLabel(centralWidget);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(9, 17, 30, 16));
        label->setAlignment(Qt::AlignCenter);
        label_2 = new QLabel(centralWidget);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setGeometry(QRect(9, 51, 36, 16));
        label_2->setAlignment(Qt::AlignCenter);
        CSetDialogClass->setCentralWidget(centralWidget);

        retranslateUi(CSetDialogClass);

        QMetaObject::connectSlotsByName(CSetDialogClass);
    } // setupUi

    void retranslateUi(QMainWindow *CSetDialogClass)
    {
        CSetDialogClass->setWindowTitle(QApplication::translate("CSetDialogClass", "CSetDialog", 0, QApplication::UnicodeUTF8));
        pushButton_OK->setText(QApplication::translate("CSetDialogClass", "\347\241\256\345\256\232", 0, QApplication::UnicodeUTF8));
        pushButton_Cancel->setText(QApplication::translate("CSetDialogClass", "\345\217\226\346\266\210", 0, QApplication::UnicodeUTF8));
        label->setText(QApplication::translate("CSetDialogClass", "\345\247\223\345\220\215:", 0, QApplication::UnicodeUTF8));
        label_2->setText(QApplication::translate("CSetDialogClass", "\346\240\274\350\250\200\357\274\232", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CSetDialogClass: public Ui_CSetDialogClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CSETDIALOG_H
