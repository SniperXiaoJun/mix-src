/********************************************************************************
** Form generated from reading UI file 'CChatDialog.ui'
**
** Created: Fri Dec 2 15:29:08 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CCHATDIALOG_H
#define UI_CCHATDIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QTextEdit>
#include <QtGui/QToolBar>
#include <QtGui/QTreeWidget>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CChatDialogClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout_Frame;
    QWidget *widget_3;
    QGridLayout *gridLayout_3;
    QTextEdit *textEdit_All;
    QWidget *widget_2;
    QGridLayout *gridLayout;
    QPushButton *pushButton_Font;
    QPushButton *pushButton_Color;
    QPushButton *pushButton_File;
    QPushButton *pushButton_Img;
    QTextEdit *textEdit_Send;
    QWidget *widget;
    QGridLayout *gridLayout_2;
    QPushButton *pushButton_Send;
    QPushButton *pushButton_Log;
    QPushButton *pushButton_Cancel;
    QWidget *widget_4;
    QGridLayout *gridLayout_4;
    QTreeWidget *treeWidget_USR;
    QTreeWidget *treeWidget_FILE_SEND;
    QTreeWidget *treeWidget_FILE_RECV;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;

    void setupUi(QMainWindow *CChatDialogClass)
    {
        if (CChatDialogClass->objectName().isEmpty())
            CChatDialogClass->setObjectName(QString::fromUtf8("CChatDialogClass"));
        CChatDialogClass->resize(524, 500);
        centralWidget = new QWidget(CChatDialogClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout_Frame = new QGridLayout(centralWidget);
        gridLayout_Frame->setSpacing(6);
        gridLayout_Frame->setContentsMargins(11, 11, 11, 11);
        gridLayout_Frame->setObjectName(QString::fromUtf8("gridLayout_Frame"));
        widget_3 = new QWidget(centralWidget);
        widget_3->setObjectName(QString::fromUtf8("widget_3"));
        gridLayout_3 = new QGridLayout(widget_3);
        gridLayout_3->setSpacing(0);
        gridLayout_3->setContentsMargins(0, 0, 0, 0);
        gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));
        textEdit_All = new QTextEdit(widget_3);
        textEdit_All->setObjectName(QString::fromUtf8("textEdit_All"));
        textEdit_All->setReadOnly(true);

        gridLayout_3->addWidget(textEdit_All, 0, 0, 1, 1);

        widget_2 = new QWidget(widget_3);
        widget_2->setObjectName(QString::fromUtf8("widget_2"));
        gridLayout = new QGridLayout(widget_2);
        gridLayout->setSpacing(0);
        gridLayout->setContentsMargins(0, 0, 0, 0);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        pushButton_Font = new QPushButton(widget_2);
        pushButton_Font->setObjectName(QString::fromUtf8("pushButton_Font"));

        gridLayout->addWidget(pushButton_Font, 0, 0, 1, 1);

        pushButton_Color = new QPushButton(widget_2);
        pushButton_Color->setObjectName(QString::fromUtf8("pushButton_Color"));

        gridLayout->addWidget(pushButton_Color, 0, 1, 1, 1);

        pushButton_File = new QPushButton(widget_2);
        pushButton_File->setObjectName(QString::fromUtf8("pushButton_File"));

        gridLayout->addWidget(pushButton_File, 0, 3, 1, 1);

        pushButton_Img = new QPushButton(widget_2);
        pushButton_Img->setObjectName(QString::fromUtf8("pushButton_Img"));

        gridLayout->addWidget(pushButton_Img, 0, 2, 1, 1);


        gridLayout_3->addWidget(widget_2, 1, 0, 1, 1);

        textEdit_Send = new QTextEdit(widget_3);
        textEdit_Send->setObjectName(QString::fromUtf8("textEdit_Send"));
        textEdit_Send->setMinimumSize(QSize(300, 100));
        textEdit_Send->setMaximumSize(QSize(300, 100));
        textEdit_Send->setSizeIncrement(QSize(0, 0));
        textEdit_Send->setBaseSize(QSize(0, 0));

        gridLayout_3->addWidget(textEdit_Send, 2, 0, 1, 1);

        widget = new QWidget(widget_3);
        widget->setObjectName(QString::fromUtf8("widget"));
        gridLayout_2 = new QGridLayout(widget);
        gridLayout_2->setSpacing(6);
        gridLayout_2->setContentsMargins(11, 11, 11, 11);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        gridLayout_2->setContentsMargins(-1, -1, -1, 0);
        pushButton_Send = new QPushButton(widget);
        pushButton_Send->setObjectName(QString::fromUtf8("pushButton_Send"));

        gridLayout_2->addWidget(pushButton_Send, 0, 0, 1, 1);

        pushButton_Log = new QPushButton(widget);
        pushButton_Log->setObjectName(QString::fromUtf8("pushButton_Log"));

        gridLayout_2->addWidget(pushButton_Log, 0, 1, 1, 1);

        pushButton_Cancel = new QPushButton(widget);
        pushButton_Cancel->setObjectName(QString::fromUtf8("pushButton_Cancel"));

        gridLayout_2->addWidget(pushButton_Cancel, 0, 2, 1, 1);


        gridLayout_3->addWidget(widget, 3, 0, 1, 1);


        gridLayout_Frame->addWidget(widget_3, 0, 0, 1, 1);

        widget_4 = new QWidget(centralWidget);
        widget_4->setObjectName(QString::fromUtf8("widget_4"));
        gridLayout_4 = new QGridLayout(widget_4);
        gridLayout_4->setSpacing(0);
        gridLayout_4->setContentsMargins(0, 0, 0, 0);
        gridLayout_4->setObjectName(QString::fromUtf8("gridLayout_4"));
        treeWidget_USR = new QTreeWidget(widget_4);
        treeWidget_USR->setObjectName(QString::fromUtf8("treeWidget_USR"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(treeWidget_USR->sizePolicy().hasHeightForWidth());
        treeWidget_USR->setSizePolicy(sizePolicy);
        treeWidget_USR->setMinimumSize(QSize(0, 0));
        treeWidget_USR->setMaximumSize(QSize(16777215, 16777215));
        treeWidget_USR->setSizeIncrement(QSize(0, 0));

        gridLayout_4->addWidget(treeWidget_USR, 0, 0, 1, 1);

        treeWidget_FILE_SEND = new QTreeWidget(widget_4);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("\346\226\207\344\273\266\345\220\215"));
        treeWidget_FILE_SEND->setHeaderItem(__qtreewidgetitem);
        treeWidget_FILE_SEND->setObjectName(QString::fromUtf8("treeWidget_FILE_SEND"));
        treeWidget_FILE_SEND->setMinimumSize(QSize(200, 150));
        treeWidget_FILE_SEND->setMaximumSize(QSize(200, 150));

        gridLayout_4->addWidget(treeWidget_FILE_SEND, 1, 0, 1, 1);

        treeWidget_FILE_RECV = new QTreeWidget(widget_4);
        treeWidget_FILE_RECV->setObjectName(QString::fromUtf8("treeWidget_FILE_RECV"));

        gridLayout_4->addWidget(treeWidget_FILE_RECV, 2, 0, 1, 1);


        gridLayout_Frame->addWidget(widget_4, 0, 1, 1, 1);

        CChatDialogClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CChatDialogClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 524, 20));
        CChatDialogClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(CChatDialogClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        CChatDialogClass->addToolBar(Qt::TopToolBarArea, mainToolBar);

        retranslateUi(CChatDialogClass);

        QMetaObject::connectSlotsByName(CChatDialogClass);
    } // setupUi

    void retranslateUi(QMainWindow *CChatDialogClass)
    {
        CChatDialogClass->setWindowTitle(QApplication::translate("CChatDialogClass", "CChatDialog", 0, QApplication::UnicodeUTF8));
        pushButton_Font->setText(QApplication::translate("CChatDialogClass", "\345\255\227\344\275\223", 0, QApplication::UnicodeUTF8));
        pushButton_Color->setText(QApplication::translate("CChatDialogClass", "\351\242\234\350\211\262", 0, QApplication::UnicodeUTF8));
        pushButton_File->setText(QApplication::translate("CChatDialogClass", "\346\226\207\344\273\266", 0, QApplication::UnicodeUTF8));
        pushButton_Img->setText(QApplication::translate("CChatDialogClass", "\345\233\276\347\211\207", 0, QApplication::UnicodeUTF8));
        pushButton_Send->setText(QApplication::translate("CChatDialogClass", "\345\217\221\351\200\201", 0, QApplication::UnicodeUTF8));
        pushButton_Log->setText(QApplication::translate("CChatDialogClass", "\350\201\212\345\244\251\350\256\260\345\275\225", 0, QApplication::UnicodeUTF8));
        pushButton_Cancel->setText(QApplication::translate("CChatDialogClass", "\345\205\263\351\227\255", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem = treeWidget_USR->headerItem();
        ___qtreewidgetitem->setText(2, QApplication::translate("CChatDialogClass", "\346\240\274\350\250\200", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem->setText(1, QApplication::translate("CChatDialogClass", "IP", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem->setText(0, QApplication::translate("CChatDialogClass", "\345\220\215\347\247\260", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem1 = treeWidget_FILE_SEND->headerItem();
        ___qtreewidgetitem1->setText(3, QApplication::translate("CChatDialogClass", "\350\277\233\345\272\246", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem1->setText(2, QApplication::translate("CChatDialogClass", "\350\267\257\345\276\204", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem1->setText(1, QApplication::translate("CChatDialogClass", "\345\244\247\345\260\217", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem2 = treeWidget_FILE_RECV->headerItem();
        ___qtreewidgetitem2->setText(3, QApplication::translate("CChatDialogClass", "\350\277\233\345\272\246", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem2->setText(2, QApplication::translate("CChatDialogClass", "\350\267\257\345\276\204", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem2->setText(1, QApplication::translate("CChatDialogClass", "\345\244\247\345\260\217", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem2->setText(0, QApplication::translate("CChatDialogClass", "\346\226\207\344\273\266\345\220\215", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CChatDialogClass: public Ui_CChatDialogClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CCHATDIALOG_H
