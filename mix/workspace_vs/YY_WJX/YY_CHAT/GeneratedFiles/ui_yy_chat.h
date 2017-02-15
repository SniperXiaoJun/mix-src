/********************************************************************************
** Form generated from reading UI file 'yy_chat.ui'
**
** Created: Fri Dec 2 15:06:58 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_YY_CHAT_H
#define UI_YY_CHAT_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QCalendarWidget>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QPushButton>
#include <QtGui/QStatusBar>
#include <QtGui/QToolBox>
#include <QtGui/QTreeWidget>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_YY_CHATClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QToolBox *toolBox;
    QWidget *page_Chat;
    QGridLayout *gridLayout_2;
    QTreeWidget *treeWidget_Chat;
    QWidget *page;
    QGridLayout *gridLayout_4;
    QTreeWidget *treeWidget_ChatGroup;
    QWidget *page_Calendar;
    QGridLayout *gridLayout_3;
    QCalendarWidget *calendarWidget;
    QLineEdit *lineEdit_Note;
    QPushButton *pushButton_SetCenter;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *YY_CHATClass)
    {
        if (YY_CHATClass->objectName().isEmpty())
            YY_CHATClass->setObjectName(QString::fromUtf8("YY_CHATClass"));
        YY_CHATClass->resize(228, 470);
        centralWidget = new QWidget(YY_CHATClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        toolBox = new QToolBox(centralWidget);
        toolBox->setObjectName(QString::fromUtf8("toolBox"));
        page_Chat = new QWidget();
        page_Chat->setObjectName(QString::fromUtf8("page_Chat"));
        page_Chat->setGeometry(QRect(0, 0, 210, 326));
        gridLayout_2 = new QGridLayout(page_Chat);
        gridLayout_2->setSpacing(6);
        gridLayout_2->setContentsMargins(11, 11, 11, 11);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        treeWidget_Chat = new QTreeWidget(page_Chat);
        treeWidget_Chat->setObjectName(QString::fromUtf8("treeWidget_Chat"));
        treeWidget_Chat->setAutoExpandDelay(-1);

        gridLayout_2->addWidget(treeWidget_Chat, 0, 0, 1, 1);

        toolBox->addItem(page_Chat, QString::fromUtf8("YY\350\201\212\345\244\251"));
        page = new QWidget();
        page->setObjectName(QString::fromUtf8("page"));
        page->setGeometry(QRect(0, 0, 210, 326));
        gridLayout_4 = new QGridLayout(page);
        gridLayout_4->setSpacing(6);
        gridLayout_4->setContentsMargins(11, 11, 11, 11);
        gridLayout_4->setObjectName(QString::fromUtf8("gridLayout_4"));
        treeWidget_ChatGroup = new QTreeWidget(page);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeWidget_ChatGroup->setHeaderItem(__qtreewidgetitem);
        treeWidget_ChatGroup->setObjectName(QString::fromUtf8("treeWidget_ChatGroup"));

        gridLayout_4->addWidget(treeWidget_ChatGroup, 0, 0, 1, 1);

        toolBox->addItem(page, QString::fromUtf8("YY\347\276\244\350\201\212"));
        page_Calendar = new QWidget();
        page_Calendar->setObjectName(QString::fromUtf8("page_Calendar"));
        page_Calendar->setGeometry(QRect(0, 0, 338, 310));
        gridLayout_3 = new QGridLayout(page_Calendar);
        gridLayout_3->setSpacing(6);
        gridLayout_3->setContentsMargins(11, 11, 11, 11);
        gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));
        calendarWidget = new QCalendarWidget(page_Calendar);
        calendarWidget->setObjectName(QString::fromUtf8("calendarWidget"));

        gridLayout_3->addWidget(calendarWidget, 0, 0, 1, 1);

        toolBox->addItem(page_Calendar, QString::fromUtf8("\346\227\245\345\216\206\346\227\245\346\234\237"));

        gridLayout->addWidget(toolBox, 2, 0, 1, 3);

        lineEdit_Note = new QLineEdit(centralWidget);
        lineEdit_Note->setObjectName(QString::fromUtf8("lineEdit_Note"));

        gridLayout->addWidget(lineEdit_Note, 0, 1, 1, 1);

        pushButton_SetCenter = new QPushButton(centralWidget);
        pushButton_SetCenter->setObjectName(QString::fromUtf8("pushButton_SetCenter"));

        gridLayout->addWidget(pushButton_SetCenter, 0, 0, 1, 1);

        YY_CHATClass->setCentralWidget(centralWidget);
        statusBar = new QStatusBar(YY_CHATClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        YY_CHATClass->setStatusBar(statusBar);

        retranslateUi(YY_CHATClass);

        toolBox->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(YY_CHATClass);
    } // setupUi

    void retranslateUi(QMainWindow *YY_CHATClass)
    {
        YY_CHATClass->setWindowTitle(QApplication::translate("YY_CHATClass", "YY_CHAT", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem = treeWidget_Chat->headerItem();
        ___qtreewidgetitem->setText(2, QApplication::translate("YY_CHATClass", "\346\240\274\350\250\200", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem->setText(1, QApplication::translate("YY_CHATClass", "\345\247\223\345\220\215", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem->setText(0, QApplication::translate("YY_CHATClass", "IP", 0, QApplication::UnicodeUTF8));
        toolBox->setItemText(toolBox->indexOf(page_Chat), QApplication::translate("YY_CHATClass", "YY\350\201\212\345\244\251", 0, QApplication::UnicodeUTF8));
        toolBox->setItemText(toolBox->indexOf(page), QApplication::translate("YY_CHATClass", "YY\347\276\244\350\201\212", 0, QApplication::UnicodeUTF8));
        toolBox->setItemText(toolBox->indexOf(page_Calendar), QApplication::translate("YY_CHATClass", "\346\227\245\345\216\206\346\227\245\346\234\237", 0, QApplication::UnicodeUTF8));
        pushButton_SetCenter->setText(QApplication::translate("YY_CHATClass", "\350\256\276\347\275\256\344\270\255\345\277\203", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class YY_CHATClass: public Ui_YY_CHATClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_YY_CHAT_H
