/********************************************************************************
** Form generated from reading UI file 'qtestnetrork.ui'
**
** Created: Wed Jun 19 15:04:45 2013
**      by: Qt User Interface Compiler version 4.8.4
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QTESTNETRORK_H
#define UI_QTESTNETRORK_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QProgressBar>
#include <QtGui/QPushButton>
#include <QtGui/QStatusBar>
#include <QtGui/QTextEdit>
#include <QtGui/QToolBar>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_QTestNetrorkClass
{
public:
    QWidget *centralWidget;
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QLineEdit *lineEdit;
    QProgressBar *progressBar;
    QTextEdit *textEdit;
    QPushButton *pushButton;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *QTestNetrorkClass)
    {
        if (QTestNetrorkClass->objectName().isEmpty())
            QTestNetrorkClass->setObjectName(QString::fromUtf8("QTestNetrorkClass"));
        QTestNetrorkClass->resize(477, 400);
        centralWidget = new QWidget(QTestNetrorkClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        verticalLayout = new QVBoxLayout(centralWidget);
        verticalLayout->setSpacing(6);
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        label = new QLabel(centralWidget);
        label->setObjectName(QString::fromUtf8("label"));

        verticalLayout->addWidget(label);

        lineEdit = new QLineEdit(centralWidget);
        lineEdit->setObjectName(QString::fromUtf8("lineEdit"));

        verticalLayout->addWidget(lineEdit);

        progressBar = new QProgressBar(centralWidget);
        progressBar->setObjectName(QString::fromUtf8("progressBar"));
        progressBar->setValue(24);

        verticalLayout->addWidget(progressBar);

        textEdit = new QTextEdit(centralWidget);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));

        verticalLayout->addWidget(textEdit);

        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        verticalLayout->addWidget(pushButton);

        QTestNetrorkClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(QTestNetrorkClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 477, 23));
        QTestNetrorkClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(QTestNetrorkClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        QTestNetrorkClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(QTestNetrorkClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        QTestNetrorkClass->setStatusBar(statusBar);

        retranslateUi(QTestNetrorkClass);

        QMetaObject::connectSlotsByName(QTestNetrorkClass);
    } // setupUi

    void retranslateUi(QMainWindow *QTestNetrorkClass)
    {
        QTestNetrorkClass->setWindowTitle(QApplication::translate("QTestNetrorkClass", "QTestNetrork", 0, QApplication::UnicodeUTF8));
        label->setText(QApplication::translate("QTestNetrorkClass", "\350\276\223\345\205\245URL", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("QTestNetrorkClass", "\345\274\200\345\247\213\344\270\213\350\275\275", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class QTestNetrorkClass: public Ui_QTestNetrorkClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QTESTNETRORK_H
