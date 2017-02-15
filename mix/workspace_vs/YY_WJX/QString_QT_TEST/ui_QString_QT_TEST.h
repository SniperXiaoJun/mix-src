/********************************************************************************
** Form generated from reading UI file 'QString_QT_TEST.ui'
**
** Created: Fri Apr 1 12:06:31 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QSTRING_QT_TEST_H
#define UI_QSTRING_QT_TEST_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QStatusBar>
#include <QtGui/QTextEdit>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_QString_QT_TEST
{
public:
    QWidget *centralwidget;
    QGridLayout *gridLayout;
    QTextEdit *textEdit;
    QPushButton *pushButton;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *QString_QT_TEST)
    {
        if (QString_QT_TEST->objectName().isEmpty())
            QString_QT_TEST->setObjectName(QString::fromUtf8("QString_QT_TEST"));
        QString_QT_TEST->resize(188, 203);
        centralwidget = new QWidget(QString_QT_TEST);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        gridLayout = new QGridLayout(centralwidget);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        textEdit = new QTextEdit(centralwidget);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));

        gridLayout->addWidget(textEdit, 0, 0, 1, 1);

        pushButton = new QPushButton(centralwidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        gridLayout->addWidget(pushButton, 1, 0, 1, 1);

        QString_QT_TEST->setCentralWidget(centralwidget);
        menubar = new QMenuBar(QString_QT_TEST);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 188, 21));
        QString_QT_TEST->setMenuBar(menubar);
        statusbar = new QStatusBar(QString_QT_TEST);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        QString_QT_TEST->setStatusBar(statusbar);

        retranslateUi(QString_QT_TEST);

        QMetaObject::connectSlotsByName(QString_QT_TEST);
    } // setupUi

    void retranslateUi(QMainWindow *QString_QT_TEST)
    {
        QString_QT_TEST->setWindowTitle(QApplication::translate("QString_QT_TEST", "QString_QT_TEST", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("QString_QT_TEST", "\345\241\253\345\212\240\344\270\200\346\235\241", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class QString_QT_TEST: public Ui_QString_QT_TEST {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QSTRING_QT_TEST_H
