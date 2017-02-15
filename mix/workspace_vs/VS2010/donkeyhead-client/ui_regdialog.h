/********************************************************************************
** Form generated from reading UI file 'regdialog.ui'
**
** Created: Fri Jun 15 17:44:27 2012
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_REGDIALOG_H
#define UI_REGDIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QDialog>
#include <QtGui/QHeaderView>
#include <QtGui/QLineEdit>
#include <QtGui/QPushButton>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_regdialog
{
public:
    QWidget *widget;
    QLineEdit *usrnamelineEdit;
    QLineEdit *passwordlineEdit;
    QLineEdit *password2lineEdit;
    QLineEdit *nicknamelineEdit;
    QPushButton *submitButton;
    QPushButton *cancelButton;

    void setupUi(QDialog *regdialog)
    {
        if (regdialog->objectName().isEmpty())
            regdialog->setObjectName(QString::fromUtf8("regdialog"));
        regdialog->resize(400, 354);
        regdialog->setMinimumSize(QSize(400, 354));
        regdialog->setMaximumSize(QSize(400, 354));
        regdialog->setAcceptDrops(false);
        regdialog->setStyleSheet(QString::fromUtf8(""));
        widget = new QWidget(regdialog);
        widget->setObjectName(QString::fromUtf8("widget"));
        widget->setGeometry(QRect(0, 0, 400, 354));
        widget->setMinimumSize(QSize(400, 354));
        widget->setMaximumSize(QSize(400, 354));
        widget->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/res/register.png);"));
        usrnamelineEdit = new QLineEdit(widget);
        usrnamelineEdit->setObjectName(QString::fromUtf8("usrnamelineEdit"));
        usrnamelineEdit->setGeometry(QRect(120, 160, 133, 20));
        usrnamelineEdit->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
        passwordlineEdit = new QLineEdit(widget);
        passwordlineEdit->setObjectName(QString::fromUtf8("passwordlineEdit"));
        passwordlineEdit->setGeometry(QRect(120, 190, 133, 20));
        passwordlineEdit->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
        passwordlineEdit->setEchoMode(QLineEdit::Password);
        password2lineEdit = new QLineEdit(widget);
        password2lineEdit->setObjectName(QString::fromUtf8("password2lineEdit"));
        password2lineEdit->setGeometry(QRect(120, 230, 133, 20));
        password2lineEdit->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
        password2lineEdit->setEchoMode(QLineEdit::Password);
        nicknamelineEdit = new QLineEdit(widget);
        nicknamelineEdit->setObjectName(QString::fromUtf8("nicknamelineEdit"));
        nicknamelineEdit->setGeometry(QRect(120, 260, 133, 20));
        nicknamelineEdit->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
        submitButton = new QPushButton(widget);
        submitButton->setObjectName(QString::fromUtf8("submitButton"));
        submitButton->setGeometry(QRect(76, 296, 53, 21));
        QFont font;
        font.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        submitButton->setFont(font);
        submitButton->setStyleSheet(QString::fromUtf8(""));
        cancelButton = new QPushButton(widget);
        cancelButton->setObjectName(QString::fromUtf8("cancelButton"));
        cancelButton->setGeometry(QRect(256, 292, 49, 25));
        cancelButton->setFont(font);

        retranslateUi(regdialog);

        QMetaObject::connectSlotsByName(regdialog);
    } // setupUi

    void retranslateUi(QDialog *regdialog)
    {
        regdialog->setWindowTitle(QApplication::translate("regdialog", "Dialog", 0, QApplication::UnicodeUTF8));
        submitButton->setText(QApplication::translate("regdialog", "\347\241\256\345\256\232", 0, QApplication::UnicodeUTF8));
        cancelButton->setText(QApplication::translate("regdialog", "\345\217\226\346\266\210", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class regdialog: public Ui_regdialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_REGDIALOG_H
