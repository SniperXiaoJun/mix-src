/********************************************************************************
** Form generated from reading UI file 'login.ui'
**
** Created: Fri Jun 15 17:44:27 2012
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_LOGIN_H
#define UI_LOGIN_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QPushButton>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_login
{
public:
    QWidget *centralWidget;
    QPushButton *loginButton;
    QLineEdit *passwordlineEdit;
    QPushButton *cancelpushButton;
    QPushButton *submitpushButton;
    QPushButton *setButton;
    QLineEdit *usrnamelineEdit;
    QPushButton *regButton;
    QPushButton *findpwdButton;
    QLineEdit *iplineEdit;
    QLineEdit *portlineEdit;
    QPushButton *pushButton;

    void setupUi(QMainWindow *login)
    {
        if (login->objectName().isEmpty())
            login->setObjectName(QString::fromUtf8("login"));
        login->setEnabled(true);
        login->resize(602, 578);
        centralWidget = new QWidget(login);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        centralWidget->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/7.png);"));
        loginButton = new QPushButton(centralWidget);
        loginButton->setObjectName(QString::fromUtf8("loginButton"));
        loginButton->setGeometry(QRect(280, 288, 45, 23));
        QFont font;
        font.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        loginButton->setFont(font);
        loginButton->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back.png);"));
        loginButton->setFlat(false);
        passwordlineEdit = new QLineEdit(centralWidget);
        passwordlineEdit->setObjectName(QString::fromUtf8("passwordlineEdit"));
        passwordlineEdit->setGeometry(QRect(116, 236, 137, 20));
        passwordlineEdit->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back1.png);"));
        passwordlineEdit->setEchoMode(QLineEdit::Password);
        cancelpushButton = new QPushButton(centralWidget);
        cancelpushButton->setObjectName(QString::fromUtf8("cancelpushButton"));
        cancelpushButton->setGeometry(QRect(252, 516, 49, 23));
        cancelpushButton->setFont(font);
        cancelpushButton->setAutoFillBackground(false);
        cancelpushButton->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back.png);"));
        submitpushButton = new QPushButton(centralWidget);
        submitpushButton->setObjectName(QString::fromUtf8("submitpushButton"));
        submitpushButton->setGeometry(QRect(84, 516, 49, 23));
        submitpushButton->setFont(font);
        submitpushButton->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back.png);"));
        setButton = new QPushButton(centralWidget);
        setButton->setObjectName(QString::fromUtf8("setButton"));
        setButton->setGeometry(QRect(68, 288, 41, 25));
        setButton->setFont(font);
        setButton->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back.png);"));
        usrnamelineEdit = new QLineEdit(centralWidget);
        usrnamelineEdit->setObjectName(QString::fromUtf8("usrnamelineEdit"));
        usrnamelineEdit->setGeometry(QRect(116, 192, 137, 20));
        usrnamelineEdit->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back1.png);"));
        usrnamelineEdit->setDragEnabled(false);
        regButton = new QPushButton(centralWidget);
        regButton->setObjectName(QString::fromUtf8("regButton"));
        regButton->setGeometry(QRect(272, 196, 65, 17));
        regButton->setFont(font);
        regButton->setStyleSheet(QString::fromUtf8("color: rgb(0, 85, 255);\n"
"background-image: url(:/new/prefix1/back1.png);"));
        regButton->setFlat(true);
        findpwdButton = new QPushButton(centralWidget);
        findpwdButton->setObjectName(QString::fromUtf8("findpwdButton"));
        findpwdButton->setGeometry(QRect(276, 236, 53, 17));
        findpwdButton->setFont(font);
        findpwdButton->setStyleSheet(QString::fromUtf8("color: rgb(0, 85, 255);\n"
"background-image: url(:/new/prefix1/back1.png);"));
        findpwdButton->setFlat(true);
        iplineEdit = new QLineEdit(centralWidget);
        iplineEdit->setObjectName(QString::fromUtf8("iplineEdit"));
        iplineEdit->setGeometry(QRect(140, 432, 141, 20));
        iplineEdit->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back.png);"));
        iplineEdit->setDragEnabled(false);
        portlineEdit = new QLineEdit(centralWidget);
        portlineEdit->setObjectName(QString::fromUtf8("portlineEdit"));
        portlineEdit->setGeometry(QRect(140, 460, 141, 20));
        portlineEdit->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back.png);"));
        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));
        pushButton->setGeometry(QRect(340, 108, 21, 17));
        QFont font1;
        font1.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        font1.setPointSize(12);
        font1.setBold(true);
        font1.setWeight(75);
        pushButton->setFont(font1);
        pushButton->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back1.png);"));
        pushButton->setFlat(true);
        login->setCentralWidget(centralWidget);

        retranslateUi(login);
        QObject::connect(pushButton, SIGNAL(clicked()), login, SLOT(close()));

        QMetaObject::connectSlotsByName(login);
    } // setupUi

    void retranslateUi(QMainWindow *login)
    {
        login->setWindowTitle(QApplication::translate("login", "login", 0, QApplication::UnicodeUTF8));
        loginButton->setText(QApplication::translate("login", "\347\231\273\351\231\206", 0, QApplication::UnicodeUTF8));
        cancelpushButton->setText(QApplication::translate("login", "\345\217\226\346\266\210", 0, QApplication::UnicodeUTF8));
        submitpushButton->setText(QApplication::translate("login", "\347\241\256\345\256\232", 0, QApplication::UnicodeUTF8));
        setButton->setText(QApplication::translate("login", "\350\256\276\347\275\256", 0, QApplication::UnicodeUTF8));
        regButton->setText(QApplication::translate("login", "\346\263\250\345\206\214\346\226\260\350\264\246\345\217\267", 0, QApplication::UnicodeUTF8));
        findpwdButton->setText(QApplication::translate("login", "\346\211\276\345\233\236\345\257\206\347\240\201", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("login", "X", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class login: public Ui_login {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_LOGIN_H
