/********************************************************************************
** Form generated from reading UI file 'CWriteMSUI.ui'
**
** Created: Mon Jul 11 10:22:57 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CWRITEMSUI_H
#define UI_CWRITEMSUI_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHBoxLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QScrollArea>
#include <QtGui/QTextBrowser>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CWriteMSUIClass
{
public:
    QAction *pactionExit;
    QAction *pactionSend;
    QAction *pactionNext;
    QAction *pactionInsertImage;
    QAction *pactionAddPage;
    QAction *pactionDelPage;
    QAction *pactionSave;
    QAction *pactionBack;
    QAction *pactionAddUser;
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;
    QGridLayout *gridLayout_2;
    QLabel *pSenderLabel;
    QLineEdit *pSenderLineEdit;
    QLabel *pReceiverLabel;
    QLineEdit *pReceiverLineEdit;
    QLabel *pThemeLabel;
    QLineEdit *pThemeLineEdit;
    QTextBrowser *pmessagetextBrowser;
    QWidget *widget;
    QHBoxLayout *horizontalLayout;
    QPushButton *pushButtonBack;
    QLabel *labelPage;
    QPushButton *pushButtonNext;
    QMenuBar *menuBar;
    QMenu *menu_File;

    void setupUi(QMainWindow *CWriteMSUIClass)
    {
        if (CWriteMSUIClass->objectName().isEmpty())
            CWriteMSUIClass->setObjectName(QString::fromUtf8("CWriteMSUIClass"));
        CWriteMSUIClass->resize(240, 320);
        CWriteMSUIClass->setStyleSheet(QString::fromUtf8(""));
        pactionExit = new QAction(CWriteMSUIClass);
        pactionExit->setObjectName(QString::fromUtf8("pactionExit"));
        pactionSend = new QAction(CWriteMSUIClass);
        pactionSend->setObjectName(QString::fromUtf8("pactionSend"));
        pactionNext = new QAction(CWriteMSUIClass);
        pactionNext->setObjectName(QString::fromUtf8("pactionNext"));
        pactionInsertImage = new QAction(CWriteMSUIClass);
        pactionInsertImage->setObjectName(QString::fromUtf8("pactionInsertImage"));
        pactionAddPage = new QAction(CWriteMSUIClass);
        pactionAddPage->setObjectName(QString::fromUtf8("pactionAddPage"));
        pactionDelPage = new QAction(CWriteMSUIClass);
        pactionDelPage->setObjectName(QString::fromUtf8("pactionDelPage"));
        pactionSave = new QAction(CWriteMSUIClass);
        pactionSave->setObjectName(QString::fromUtf8("pactionSave"));
        pactionBack = new QAction(CWriteMSUIClass);
        pactionBack->setObjectName(QString::fromUtf8("pactionBack"));
        pactionAddUser = new QAction(CWriteMSUIClass);
        pactionAddUser->setObjectName(QString::fromUtf8("pactionAddUser"));
        centralWidget = new QWidget(CWriteMSUIClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        scrollArea = new QScrollArea(centralWidget);
        scrollArea->setObjectName(QString::fromUtf8("scrollArea"));
        scrollArea->setStyleSheet(QString::fromUtf8(""));
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName(QString::fromUtf8("scrollAreaWidgetContents"));
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 218, 280));
        gridLayout_2 = new QGridLayout(scrollAreaWidgetContents);
        gridLayout_2->setSpacing(6);
        gridLayout_2->setContentsMargins(11, 11, 11, 11);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        pSenderLabel = new QLabel(scrollAreaWidgetContents);
        pSenderLabel->setObjectName(QString::fromUtf8("pSenderLabel"));

        gridLayout_2->addWidget(pSenderLabel, 0, 0, 1, 1);

        pSenderLineEdit = new QLineEdit(scrollAreaWidgetContents);
        pSenderLineEdit->setObjectName(QString::fromUtf8("pSenderLineEdit"));
        pSenderLineEdit->setAlignment(Qt::AlignCenter);
        pSenderLineEdit->setReadOnly(true);

        gridLayout_2->addWidget(pSenderLineEdit, 0, 1, 1, 1);

        pReceiverLabel = new QLabel(scrollAreaWidgetContents);
        pReceiverLabel->setObjectName(QString::fromUtf8("pReceiverLabel"));

        gridLayout_2->addWidget(pReceiverLabel, 1, 0, 1, 1);

        pReceiverLineEdit = new QLineEdit(scrollAreaWidgetContents);
        pReceiverLineEdit->setObjectName(QString::fromUtf8("pReceiverLineEdit"));
        pReceiverLineEdit->setAlignment(Qt::AlignCenter);

        gridLayout_2->addWidget(pReceiverLineEdit, 1, 1, 1, 1);

        pThemeLabel = new QLabel(scrollAreaWidgetContents);
        pThemeLabel->setObjectName(QString::fromUtf8("pThemeLabel"));

        gridLayout_2->addWidget(pThemeLabel, 2, 0, 1, 1);

        pThemeLineEdit = new QLineEdit(scrollAreaWidgetContents);
        pThemeLineEdit->setObjectName(QString::fromUtf8("pThemeLineEdit"));
        pThemeLineEdit->setAlignment(Qt::AlignCenter);

        gridLayout_2->addWidget(pThemeLineEdit, 2, 1, 1, 1);

        pmessagetextBrowser = new QTextBrowser(scrollAreaWidgetContents);
        pmessagetextBrowser->setObjectName(QString::fromUtf8("pmessagetextBrowser"));
        pmessagetextBrowser->setStyleSheet(QString::fromUtf8(""));
        pmessagetextBrowser->setReadOnly(false);

        gridLayout_2->addWidget(pmessagetextBrowser, 3, 0, 1, 2);

        widget = new QWidget(scrollAreaWidgetContents);
        widget->setObjectName(QString::fromUtf8("widget"));
        horizontalLayout = new QHBoxLayout(widget);
        horizontalLayout->setSpacing(0);
        horizontalLayout->setContentsMargins(0, 0, 0, 0);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        pushButtonBack = new QPushButton(widget);
        pushButtonBack->setObjectName(QString::fromUtf8("pushButtonBack"));

        horizontalLayout->addWidget(pushButtonBack);

        labelPage = new QLabel(widget);
        labelPage->setObjectName(QString::fromUtf8("labelPage"));
        labelPage->setAlignment(Qt::AlignCenter);

        horizontalLayout->addWidget(labelPage);

        pushButtonNext = new QPushButton(widget);
        pushButtonNext->setObjectName(QString::fromUtf8("pushButtonNext"));

        horizontalLayout->addWidget(pushButtonNext);


        gridLayout_2->addWidget(widget, 4, 0, 1, 2);

        scrollArea->setWidget(scrollAreaWidgetContents);

        gridLayout->addWidget(scrollArea, 0, 0, 1, 1);

        CWriteMSUIClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CWriteMSUIClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 240, 18));
        menu_File = new QMenu(menuBar);
        menu_File->setObjectName(QString::fromUtf8("menu_File"));
        CWriteMSUIClass->setMenuBar(menuBar);

        menuBar->addAction(menu_File->menuAction());
        menu_File->addAction(pactionExit);
        menu_File->addSeparator();
        menu_File->addAction(pactionSend);
        menu_File->addAction(pactionSave);
        menu_File->addSeparator();
        menu_File->addAction(pactionBack);
        menu_File->addAction(pactionNext);
        menu_File->addSeparator();
        menu_File->addAction(pactionInsertImage);
        menu_File->addAction(pactionAddPage);
        menu_File->addAction(pactionDelPage);
        menu_File->addAction(pactionAddUser);

        retranslateUi(CWriteMSUIClass);
        QObject::connect(pactionExit, SIGNAL(triggered()), CWriteMSUIClass, SLOT(close()));

        QMetaObject::connectSlotsByName(CWriteMSUIClass);
    } // setupUi

    void retranslateUi(QMainWindow *CWriteMSUIClass)
    {
        CWriteMSUIClass->setWindowTitle(QApplication::translate("CWriteMSUIClass", "CWriteMSUI", 0, QApplication::UnicodeUTF8));
        pactionExit->setText(QApplication::translate("CWriteMSUIClass", "\345\217\226\346\266\210|\351\200\200\345\207\272", 0, QApplication::UnicodeUTF8));
        pactionSend->setText(QApplication::translate("CWriteMSUIClass", "\345\217\221\351\200\201", 0, QApplication::UnicodeUTF8));
        pactionNext->setText(QApplication::translate("CWriteMSUIClass", "\344\270\213\344\270\200\351\241\265", 0, QApplication::UnicodeUTF8));
        pactionInsertImage->setText(QApplication::translate("CWriteMSUIClass", "\346\217\222\345\205\245\345\233\276\347\211\207", 0, QApplication::UnicodeUTF8));
        pactionAddPage->setText(QApplication::translate("CWriteMSUIClass", "\346\267\273\345\212\240\344\270\200\351\241\265", 0, QApplication::UnicodeUTF8));
        pactionDelPage->setText(QApplication::translate("CWriteMSUIClass", "\345\210\240\351\231\244\344\270\200\351\241\265", 0, QApplication::UnicodeUTF8));
        pactionSave->setText(QApplication::translate("CWriteMSUIClass", "\344\277\235\345\255\230", 0, QApplication::UnicodeUTF8));
        pactionBack->setText(QApplication::translate("CWriteMSUIClass", "\344\270\212\344\270\200\351\241\265", 0, QApplication::UnicodeUTF8));
        pactionAddUser->setText(QApplication::translate("CWriteMSUIClass", "\346\224\266\344\273\266\344\272\272", 0, QApplication::UnicodeUTF8));
        pSenderLabel->setText(QApplication::translate("CWriteMSUIClass", "\345\217\221\344\273\266\344\272\272\357\274\232", 0, QApplication::UnicodeUTF8));
        pSenderLineEdit->setText(QApplication::translate("CWriteMSUIClass", "13801234567", 0, QApplication::UnicodeUTF8));
        pReceiverLabel->setText(QApplication::translate("CWriteMSUIClass", "\346\224\266\344\273\266\344\272\272\357\274\232", 0, QApplication::UnicodeUTF8));
        pReceiverLineEdit->setText(QString());
        pThemeLabel->setText(QApplication::translate("CWriteMSUIClass", "\344\270\273   \351\242\230\357\274\232", 0, QApplication::UnicodeUTF8));
        pmessagetextBrowser->setHtml(QApplication::translate("CWriteMSUIClass", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:'\345\256\213\344\275\223'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"></p></body></html>", 0, QApplication::UnicodeUTF8));
        pushButtonBack->setText(QApplication::translate("CWriteMSUIClass", "Back", 0, QApplication::UnicodeUTF8));
        labelPage->setText(QApplication::translate("CWriteMSUIClass", "1/1", 0, QApplication::UnicodeUTF8));
        pushButtonNext->setText(QApplication::translate("CWriteMSUIClass", "Next", 0, QApplication::UnicodeUTF8));
        menu_File->setTitle(QApplication::translate("CWriteMSUIClass", "\350\217\234\345\215\225", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CWriteMSUIClass: public Ui_CWriteMSUIClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CWRITEMSUI_H
