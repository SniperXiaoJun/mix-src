/********************************************************************************
** Form generated from reading UI file 'CInbox.ui'
**
** Created: Wed Jul 6 15:20:19 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CINBOX_H
#define UI_CINBOX_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QListWidget>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CInbox
{
public:
    QAction *actionOpen;
    QAction *actionEdit;
    QAction *actionReply;
    QAction *actionDelete;
    QAction *actionHelp;
    QAction *actionExit;
    QAction *actionFold;
    QAction *action_A;
    QAction *action_B;
    QAction *action_C;
    QAction *actionSign;
    QAction *actionSignAll;
    QAction *actionCSign;
    QAction *actionCSignAll;
    QWidget *centralwidget;
    QGridLayout *gridLayout;
    QListWidget *listWidget;
    QPushButton *pushButton;
    QMenuBar *menubar;
    QMenu *menu;
    QMenu *menuMove;
    QMenu *menuSign;

    void setupUi(QMainWindow *CInbox)
    {
        if (CInbox->objectName().isEmpty())
            CInbox->setObjectName(QString::fromUtf8("CInbox"));
        CInbox->resize(240, 320);
        actionOpen = new QAction(CInbox);
        actionOpen->setObjectName(QString::fromUtf8("actionOpen"));
        actionEdit = new QAction(CInbox);
        actionEdit->setObjectName(QString::fromUtf8("actionEdit"));
        actionReply = new QAction(CInbox);
        actionReply->setObjectName(QString::fromUtf8("actionReply"));
        actionDelete = new QAction(CInbox);
        actionDelete->setObjectName(QString::fromUtf8("actionDelete"));
        actionHelp = new QAction(CInbox);
        actionHelp->setObjectName(QString::fromUtf8("actionHelp"));
        actionExit = new QAction(CInbox);
        actionExit->setObjectName(QString::fromUtf8("actionExit"));
        actionFold = new QAction(CInbox);
        actionFold->setObjectName(QString::fromUtf8("actionFold"));
        action_A = new QAction(CInbox);
        action_A->setObjectName(QString::fromUtf8("action_A"));
        action_B = new QAction(CInbox);
        action_B->setObjectName(QString::fromUtf8("action_B"));
        action_C = new QAction(CInbox);
        action_C->setObjectName(QString::fromUtf8("action_C"));
        actionSign = new QAction(CInbox);
        actionSign->setObjectName(QString::fromUtf8("actionSign"));
        actionSignAll = new QAction(CInbox);
        actionSignAll->setObjectName(QString::fromUtf8("actionSignAll"));
        actionCSign = new QAction(CInbox);
        actionCSign->setObjectName(QString::fromUtf8("actionCSign"));
        actionCSignAll = new QAction(CInbox);
        actionCSignAll->setObjectName(QString::fromUtf8("actionCSignAll"));
        centralwidget = new QWidget(CInbox);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        gridLayout = new QGridLayout(centralwidget);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        listWidget = new QListWidget(centralwidget);
        listWidget->setObjectName(QString::fromUtf8("listWidget"));

        gridLayout->addWidget(listWidget, 1, 0, 1, 1);

        pushButton = new QPushButton(centralwidget);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        gridLayout->addWidget(pushButton, 0, 0, 1, 1);

        CInbox->setCentralWidget(centralwidget);
        menubar = new QMenuBar(CInbox);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 240, 21));
        menu = new QMenu(menubar);
        menu->setObjectName(QString::fromUtf8("menu"));
        menuMove = new QMenu(menu);
        menuMove->setObjectName(QString::fromUtf8("menuMove"));
        menuSign = new QMenu(menu);
        menuSign->setObjectName(QString::fromUtf8("menuSign"));
        CInbox->setMenuBar(menubar);

        menubar->addAction(menu->menuAction());
        menu->addAction(actionOpen);
        menu->addAction(actionEdit);
        menu->addAction(actionReply);
        menu->addAction(actionDelete);
        menu->addAction(menuMove->menuAction());
        menu->addAction(menuSign->menuAction());
        menu->addAction(actionHelp);
        menu->addAction(actionExit);
        menuMove->addAction(actionFold);
        menuMove->addAction(action_A);
        menuMove->addAction(action_B);
        menuMove->addAction(action_C);
        menuSign->addAction(actionSign);
        menuSign->addAction(actionSignAll);
        menuSign->addAction(actionCSign);
        menuSign->addAction(actionCSignAll);

        retranslateUi(CInbox);

        QMetaObject::connectSlotsByName(CInbox);
    } // setupUi

    void retranslateUi(QMainWindow *CInbox)
    {
        CInbox->setWindowTitle(QApplication::translate("CInbox", "CInbox", 0, QApplication::UnicodeUTF8));
        actionOpen->setText(QApplication::translate("CInbox", "\346\211\223\345\274\200", 0, QApplication::UnicodeUTF8));
        actionEdit->setText(QApplication::translate("CInbox", "\345\206\231\345\212\240\345\257\206\344\277\241\346\201\257", 0, QApplication::UnicodeUTF8));
        actionReply->setText(QApplication::translate("CInbox", "\345\233\236\345\244\215", 0, QApplication::UnicodeUTF8));
        actionDelete->setText(QApplication::translate("CInbox", "\345\210\240\351\231\244", 0, QApplication::UnicodeUTF8));
        actionHelp->setText(QApplication::translate("CInbox", "\345\270\256\345\212\251", 0, QApplication::UnicodeUTF8));
        actionExit->setText(QApplication::translate("CInbox", "\351\200\200\345\207\272", 0, QApplication::UnicodeUTF8));
        actionFold->setText(QApplication::translate("CInbox", "\345\212\240\345\257\206\346\226\207\344\273\266\345\244\271", 0, QApplication::UnicodeUTF8));
        action_A->setText(QApplication::translate("CInbox", "\345\255\220\346\226\207\344\273\266\345\244\271A", 0, QApplication::UnicodeUTF8));
        action_B->setText(QApplication::translate("CInbox", "\345\255\220\346\226\207\344\273\266\345\244\271B", 0, QApplication::UnicodeUTF8));
        action_C->setText(QApplication::translate("CInbox", "\345\255\220\346\226\207\344\273\266\345\244\271C", 0, QApplication::UnicodeUTF8));
        actionSign->setText(QApplication::translate("CInbox", "\346\240\207\350\256\260", 0, QApplication::UnicodeUTF8));
        actionSignAll->setText(QApplication::translate("CInbox", "\346\240\207\350\256\260\345\205\250\351\203\250", 0, QApplication::UnicodeUTF8));
        actionCSign->setText(QApplication::translate("CInbox", "\345\217\226\346\266\210\346\240\207\350\256\260", 0, QApplication::UnicodeUTF8));
        actionCSignAll->setText(QApplication::translate("CInbox", "\345\205\250\351\203\250\345\217\226\346\266\210\346\240\207\350\256\260", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("CInbox", "PushButton", 0, QApplication::UnicodeUTF8));
        menu->setTitle(QApplication::translate("CInbox", "\350\217\234\345\215\225", 0, QApplication::UnicodeUTF8));
        menuMove->setTitle(QApplication::translate("CInbox", "\347\247\273\350\207\263\345\212\240\345\257\206\346\226\207\344\273\266\345\244\271", 0, QApplication::UnicodeUTF8));
        menuSign->setTitle(QApplication::translate("CInbox", "\346\240\207\350\256\260/\345\217\226\346\266\210\346\240\207\350\256\260", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CInbox: public Ui_CInbox {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CINBOX_H
