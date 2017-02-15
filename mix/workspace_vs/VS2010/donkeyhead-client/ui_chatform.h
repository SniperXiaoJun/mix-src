/********************************************************************************
** Form generated from reading UI file 'chatform.ui'
**
** Created: Fri Jun 15 17:44:27 2012
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CHATFORM_H
#define UI_CHATFORM_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QDialog>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QListWidget>
#include <QtGui/QPushButton>
#include <QtGui/QTextEdit>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_chatform
{
public:
    QWidget *widget;
    QListWidget *listWidget;
    QLabel *label;
    QPushButton *pushButton_2;
    QPushButton *pushButton_3;
    QPushButton *pushButton;
    QTextEdit *textEdit;
    QPushButton *sendButton;
    QPushButton *pushButton_4;

    void setupUi(QDialog *chatform)
    {
        if (chatform->objectName().isEmpty())
            chatform->setObjectName(QString::fromUtf8("chatform"));
        chatform->resize(600, 600);
        chatform->setMinimumSize(QSize(600, 600));
        chatform->setMaximumSize(QSize(600, 600));
        QFont font;
        font.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        chatform->setFont(font);
        widget = new QWidget(chatform);
        widget->setObjectName(QString::fromUtf8("widget"));
        widget->setGeometry(QRect(0, 0, 600, 600));
        widget->setMinimumSize(QSize(600, 600));
        widget->setMaximumSize(QSize(600, 600));
        widget->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/res/dialog.png);"));
        listWidget = new QListWidget(widget);
        listWidget->setObjectName(QString::fromUtf8("listWidget"));
        listWidget->setGeometry(QRect(50, 72, 421, 245));
        listWidget->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/1.jpg);"));
        label = new QLabel(widget);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(70, 330, 31, 16));
        label->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back1.png);"));
        pushButton_2 = new QPushButton(widget);
        pushButton_2->setObjectName(QString::fromUtf8("pushButton_2"));
        pushButton_2->setGeometry(QRect(130, 330, 21, 23));
        pushButton_3 = new QPushButton(widget);
        pushButton_3->setObjectName(QString::fromUtf8("pushButton_3"));
        pushButton_3->setGeometry(QRect(150, 330, 21, 23));
        pushButton = new QPushButton(widget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));
        pushButton->setGeometry(QRect(110, 330, 21, 23));
        textEdit = new QTextEdit(widget);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));
        textEdit->setGeometry(QRect(110, 430, 401, 91));
        textEdit->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back1.png);"));
        sendButton = new QPushButton(widget);
        sendButton->setObjectName(QString::fromUtf8("sendButton"));
        sendButton->setGeometry(QRect(460, 540, 75, 23));
        sendButton->setFont(font);
        sendButton->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back1.png);"));
        pushButton_4 = new QPushButton(widget);
        pushButton_4->setObjectName(QString::fromUtf8("pushButton_4"));
        pushButton_4->setGeometry(QRect(540, 30, 21, 20));
        QFont font1;
        font1.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        font1.setPointSize(16);
        font1.setBold(true);
        font1.setWeight(75);
        pushButton_4->setFont(font1);
        pushButton_4->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/white.jpg);\n"
"background-image: url(:/new/prefix1/back1.png);"));
        pushButton_4->setFlat(true);

        retranslateUi(chatform);

        QMetaObject::connectSlotsByName(chatform);
    } // setupUi

    void retranslateUi(QDialog *chatform)
    {
        chatform->setWindowTitle(QApplication::translate("chatform", "Dialog", 0, QApplication::UnicodeUTF8));
        label->setText(QApplication::translate("chatform", "\345\234\272\346\231\257\357\274\232", 0, QApplication::UnicodeUTF8));
        pushButton_2->setText(QApplication::translate("chatform", "2", 0, QApplication::UnicodeUTF8));
        pushButton_3->setText(QApplication::translate("chatform", "3", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("chatform", "1", 0, QApplication::UnicodeUTF8));
        sendButton->setText(QApplication::translate("chatform", "\345\217\221\351\200\201", 0, QApplication::UnicodeUTF8));
        pushButton_4->setText(QApplication::translate("chatform", "\303\227", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class chatform: public Ui_chatform {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CHATFORM_H
