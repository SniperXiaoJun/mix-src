/********************************************************************************
** Form generated from reading UI file 'daemon.ui'
**
** Created: Fri Jun 15 18:01:22 2012
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_DAEMON_H
#define UI_DAEMON_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QListWidget>
#include <QtGui/QMainWindow>
#include <QtGui/QPushButton>
#include <QtGui/QTableView>
#include <QtGui/QTextEdit>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_Daemon
{
public:
    QWidget *centralWidget;
    QListWidget *listWidget;
    QTextEdit *servTextEdit;
    QLineEdit *portLineEdit;
    QLabel *label;
    QPushButton *refreshButton;
    QPushButton *sendButton;
    QPushButton *startListenButton;
    QLineEdit *ipLineEdit;
    QLabel *portLabel;
    QPushButton *pushButton;
    QTableView *tableView;

    void setupUi(QMainWindow *Daemon)
    {
        if (Daemon->objectName().isEmpty())
            Daemon->setObjectName(QString::fromUtf8("Daemon"));
        Daemon->resize(600, 600);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(Daemon->sizePolicy().hasHeightForWidth());
        Daemon->setSizePolicy(sizePolicy);
        Daemon->setMinimumSize(QSize(600, 600));
        Daemon->setMaximumSize(QSize(600, 600));
        centralWidget = new QWidget(Daemon);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        centralWidget->setStyleSheet(QString::fromUtf8("image: url(:/server/server.png);"));
        listWidget = new QListWidget(centralWidget);
        listWidget->setObjectName(QString::fromUtf8("listWidget"));
        listWidget->setGeometry(QRect(320, 72, 177, 209));
        listWidget->setStyleSheet(QString::fromUtf8("background-image: url(:/server/back1.png);"));
        servTextEdit = new QTextEdit(centralWidget);
        servTextEdit->setObjectName(QString::fromUtf8("servTextEdit"));
        servTextEdit->setGeometry(QRect(320, 290, 241, 161));
        servTextEdit->setStyleSheet(QString::fromUtf8("background-image: url(:/server/back1.png);"));
        portLineEdit = new QLineEdit(centralWidget);
        portLineEdit->setObjectName(QString::fromUtf8("portLineEdit"));
        portLineEdit->setGeometry(QRect(392, 531, 133, 20));
        portLineEdit->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/white.jpg);"));
        label = new QLabel(centralWidget);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(151, 531, 48, 16));
        QFont font;
        font.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        label->setFont(font);
        label->setStyleSheet(QString::fromUtf8("image: url(:/server/back1.png);"));
        refreshButton = new QPushButton(centralWidget);
        refreshButton->setObjectName(QString::fromUtf8("refreshButton"));
        refreshButton->setGeometry(QRect(60, 480, 75, 23));
        refreshButton->setFont(font);
        refreshButton->setStyleSheet(QString::fromUtf8(""));
        sendButton = new QPushButton(centralWidget);
        sendButton->setObjectName(QString::fromUtf8("sendButton"));
        sendButton->setGeometry(QRect(450, 480, 75, 23));
        sendButton->setFont(font);
        sendButton->setStyleSheet(QString::fromUtf8(""));
        startListenButton = new QPushButton(centralWidget);
        startListenButton->setObjectName(QString::fromUtf8("startListenButton"));
        startListenButton->setGeometry(QRect(60, 530, 71, 23));
        startListenButton->setFont(font);
        startListenButton->setStyleSheet(QString::fromUtf8(""));
        ipLineEdit = new QLineEdit(centralWidget);
        ipLineEdit->setObjectName(QString::fromUtf8("ipLineEdit"));
        ipLineEdit->setGeometry(QRect(205, 531, 133, 20));
        ipLineEdit->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/white.jpg);"));
        portLabel = new QLabel(centralWidget);
        portLabel->setObjectName(QString::fromUtf8("portLabel"));
        portLabel->setGeometry(QRect(344, 531, 41, 17));
        portLabel->setFont(font);
        portLabel->setStyleSheet(QString::fromUtf8("image: url(:/server/back1.png);"));
        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));
        pushButton->setGeometry(QRect(580, 0, 21, 21));
        QFont font1;
        font1.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        font1.setPointSize(18);
        font1.setBold(true);
        font1.setWeight(75);
        pushButton->setFont(font1);
        pushButton->setFlat(true);
        tableView = new QTableView(centralWidget);
        tableView->setObjectName(QString::fromUtf8("tableView"));
        tableView->setGeometry(QRect(40, 70, 265, 381));
        Daemon->setCentralWidget(centralWidget);

        retranslateUi(Daemon);

        QMetaObject::connectSlotsByName(Daemon);
    } // setupUi

    void retranslateUi(QMainWindow *Daemon)
    {
        Daemon->setWindowTitle(QApplication::translate("Daemon", "Daemon", 0, QApplication::UnicodeUTF8));
        label->setText(QApplication::translate("Daemon", "IP\345\234\260\345\235\200\357\274\232", 0, QApplication::UnicodeUTF8));
        refreshButton->setText(QApplication::translate("Daemon", "\345\210\267\346\226\260\345\210\227\350\241\250", 0, QApplication::UnicodeUTF8));
        sendButton->setText(QApplication::translate("Daemon", "\345\217\221 \351\200\201", 0, QApplication::UnicodeUTF8));
        startListenButton->setText(QApplication::translate("Daemon", "\345\274\200\345\247\213\347\233\221\345\220\254", 0, QApplication::UnicodeUTF8));
        portLabel->setText(QApplication::translate("Daemon", "\347\253\257\345\217\243 \357\274\232", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("Daemon", "\303\227", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class Daemon: public Ui_Daemon {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_DAEMON_H
