/********************************************************************************
** Form generated from reading UI file 'panel.ui'
**
** Created: Fri Jun 15 17:44:27 2012
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PANEL_H
#define UI_PANEL_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QFrame>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QListWidget>
#include <QtGui/QMainWindow>
#include <QtGui/QPushButton>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_panel
{
public:
    QWidget *centralwidget;
    QLabel *label;
    QListWidget *usrlistWidget;
    QListWidget *serverlistWidget;
    QLabel *label_2;
    QLabel *countlabel;
    QFrame *line;
    QLineEdit *editnicknamelineEdit;
    QLabel *label_3;
    QLineEdit *editpwdlineEdit;
    QLabel *label_4;
    QPushButton *editButton;
    QPushButton *setButton;
    QPushButton *quitButton;
    QPushButton *pushButton;

    void setupUi(QMainWindow *panel)
    {
        if (panel->objectName().isEmpty())
            panel->setObjectName(QString::fromUtf8("panel"));
        panel->resize(400, 700);
        panel->setMinimumSize(QSize(400, 700));
        panel->setMaximumSize(QSize(400, 700));
        panel->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/res/panel.png);"));
        centralwidget = new QWidget(panel);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        label = new QLabel(centralwidget);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(48, 108, 56, 16));
        QFont font;
        font.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        font.setPointSize(10);
        font.setBold(false);
        font.setWeight(50);
        label->setFont(font);
        label->setStyleSheet(QString::fromUtf8(""));
        label->setScaledContents(true);
        label->setAlignment(Qt::AlignCenter);
        label->setWordWrap(false);
        usrlistWidget = new QListWidget(centralwidget);
        usrlistWidget->setObjectName(QString::fromUtf8("usrlistWidget"));
        usrlistWidget->setGeometry(QRect(56, 128, 271, 161));
        usrlistWidget->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);\n"
"background-image: url(:/new/prefix1/white.jpg);"));
        serverlistWidget = new QListWidget(centralwidget);
        serverlistWidget->setObjectName(QString::fromUtf8("serverlistWidget"));
        serverlistWidget->setGeometry(QRect(62, 330, 271, 101));
        serverlistWidget->setMaximumSize(QSize(16777215, 200));
        serverlistWidget->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back1.png);"));
        label_2 = new QLabel(centralwidget);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setGeometry(QRect(40, 310, 56, 16));
        label_2->setFont(font);
        label_2->setStyleSheet(QString::fromUtf8(""));
        label_2->setScaledContents(true);
        label_2->setAlignment(Qt::AlignCenter);
        label_2->setWordWrap(false);
        countlabel = new QLabel(centralwidget);
        countlabel->setObjectName(QString::fromUtf8("countlabel"));
        countlabel->setGeometry(QRect(52, 72, 111, 20));
        QFont font1;
        font1.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        countlabel->setFont(font1);
        line = new QFrame(centralwidget);
        line->setObjectName(QString::fromUtf8("line"));
        line->setGeometry(QRect(50, 480, 291, 20));
        line->setFrameShape(QFrame::HLine);
        line->setFrameShadow(QFrame::Sunken);
        editnicknamelineEdit = new QLineEdit(centralwidget);
        editnicknamelineEdit->setObjectName(QString::fromUtf8("editnicknamelineEdit"));
        editnicknamelineEdit->setGeometry(QRect(160, 520, 113, 31));
        editnicknamelineEdit->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
        label_3 = new QLabel(centralwidget);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        label_3->setGeometry(QRect(60, 530, 54, 12));
        label_3->setFont(font1);
        editpwdlineEdit = new QLineEdit(centralwidget);
        editpwdlineEdit->setObjectName(QString::fromUtf8("editpwdlineEdit"));
        editpwdlineEdit->setGeometry(QRect(160, 570, 113, 31));
        editpwdlineEdit->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
        label_4 = new QLabel(centralwidget);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        label_4->setGeometry(QRect(60, 580, 54, 12));
        label_4->setFont(font1);
        editButton = new QPushButton(centralwidget);
        editButton->setObjectName(QString::fromUtf8("editButton"));
        editButton->setGeometry(QRect(240, 630, 75, 23));
        editButton->setFont(font1);
        setButton = new QPushButton(centralwidget);
        setButton->setObjectName(QString::fromUtf8("setButton"));
        setButton->setGeometry(QRect(60, 450, 75, 23));
        setButton->setFont(font1);
        setButton->setStyleSheet(QString::fromUtf8(""));
        quitButton = new QPushButton(centralwidget);
        quitButton->setObjectName(QString::fromUtf8("quitButton"));
        quitButton->setGeometry(QRect(270, 450, 75, 23));
        quitButton->setFont(font1);
        quitButton->setStyleSheet(QString::fromUtf8(""));
        pushButton = new QPushButton(centralwidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));
        pushButton->setGeometry(QRect(360, 12, 25, 25));
        QFont font2;
        font2.setFamily(QString::fromUtf8("\345\276\256\350\275\257\351\233\205\351\273\221"));
        font2.setPointSize(16);
        font2.setBold(true);
        font2.setWeight(75);
        pushButton->setFont(font2);
        pushButton->setStyleSheet(QString::fromUtf8("background-image: url(:/new/prefix1/back1.png);"));
        pushButton->setFlat(true);
        panel->setCentralWidget(centralwidget);

        retranslateUi(panel);

        QMetaObject::connectSlotsByName(panel);
    } // setupUi

    void retranslateUi(QMainWindow *panel)
    {
        panel->setWindowTitle(QApplication::translate("panel", "MainWindow", 0, QApplication::UnicodeUTF8));
        label->setText(QApplication::translate("panel", "\345\245\275\345\217\213\345\210\227\350\241\250", 0, QApplication::UnicodeUTF8));
        label_2->setText(QApplication::translate("panel", "\347\263\273\347\273\237\344\277\241\346\201\257", 0, QApplication::UnicodeUTF8));
        countlabel->setText(QString());
        label_3->setText(QApplication::translate("panel", "\344\277\256\346\224\271\346\230\265\347\247\260\357\274\232", 0, QApplication::UnicodeUTF8));
        label_4->setText(QApplication::translate("panel", "\344\277\256\346\224\271\345\257\206\347\240\201\357\274\232", 0, QApplication::UnicodeUTF8));
        editButton->setText(QApplication::translate("panel", "\344\277\256\346\224\271", 0, QApplication::UnicodeUTF8));
        setButton->setText(QApplication::translate("panel", "\350\256\276\347\275\256", 0, QApplication::UnicodeUTF8));
        quitButton->setText(QApplication::translate("panel", "\351\200\200\345\207\272", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("panel", "\303\227", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class panel: public Ui_panel {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PANEL_H
