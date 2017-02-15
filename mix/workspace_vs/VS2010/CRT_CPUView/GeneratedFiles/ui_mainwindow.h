/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created: Mon Jul 8 10:58:24 2013
**      by: Qt User Interface Compiler version 4.8.4
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

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
#include <QtGui/QToolBar>
#include <QtGui/QWidget>
#include <crt_cpuview.h>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QPushButton *pushButton_Open;
    QPushButton *pushButton_Close;
    CRT_CPUView *widget_1;
    CRT_CPUView *widget_2;
    CRT_CPUView *widget_3;
    CRT_CPUView *widget_4;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(652, 498);
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        pushButton_Open = new QPushButton(centralWidget);
        pushButton_Open->setObjectName(QString::fromUtf8("pushButton_Open"));

        gridLayout->addWidget(pushButton_Open, 0, 0, 1, 1);

        pushButton_Close = new QPushButton(centralWidget);
        pushButton_Close->setObjectName(QString::fromUtf8("pushButton_Close"));

        gridLayout->addWidget(pushButton_Close, 0, 1, 1, 1);

        widget_1 = new CRT_CPUView(centralWidget);
        widget_1->setObjectName(QString::fromUtf8("widget_1"));

        gridLayout->addWidget(widget_1, 1, 0, 1, 1);

        widget_2 = new CRT_CPUView(centralWidget);
        widget_2->setObjectName(QString::fromUtf8("widget_2"));

        gridLayout->addWidget(widget_2, 1, 1, 1, 1);

        widget_3 = new CRT_CPUView(centralWidget);
        widget_3->setObjectName(QString::fromUtf8("widget_3"));

        gridLayout->addWidget(widget_3, 2, 0, 1, 1);

        widget_4 = new CRT_CPUView(centralWidget);
        widget_4->setObjectName(QString::fromUtf8("widget_4"));

        gridLayout->addWidget(widget_4, 2, 1, 1, 1);

        MainWindow->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(MainWindow);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 652, 23));
        MainWindow->setMenuBar(menuBar);
        mainToolBar = new QToolBar(MainWindow);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        MainWindow->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(MainWindow);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        MainWindow->setStatusBar(statusBar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QApplication::translate("MainWindow", "CPU\346\250\241\346\213\237", 0, QApplication::UnicodeUTF8));
        pushButton_Open->setText(QApplication::translate("MainWindow", "\345\274\200\345\247\213\347\233\221\350\247\206", 0, QApplication::UnicodeUTF8));
        pushButton_Close->setText(QApplication::translate("MainWindow", "\345\217\226\346\266\210\347\233\221\350\247\206", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
