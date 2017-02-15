/********************************************************************************
** Form generated from reading UI file 'quitwindow.ui'
**
** Created: Fri Jul 16 00:42:44 2010
**      by: Qt User Interface Compiler version 4.6.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QUITWINDOW_H
#define UI_QUITWINDOW_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QDialog>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QPushButton>

QT_BEGIN_NAMESPACE

class Ui_quitwindow
{
public:
    QLabel *label;
    QPushButton *yesButton;
    QPushButton *noButton;

    void setupUi(QDialog *quitwindow)
    {
        if (quitwindow->objectName().isEmpty())
            quitwindow->setObjectName(QString::fromUtf8("quitwindow"));
        quitwindow->resize(400, 300);
        label = new QLabel(quitwindow);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(130, 90, 171, 51));
        yesButton = new QPushButton(quitwindow);
        yesButton->setObjectName(QString::fromUtf8("yesButton"));
        yesButton->setGeometry(QRect(70, 210, 75, 23));
        noButton = new QPushButton(quitwindow);
        noButton->setObjectName(QString::fromUtf8("noButton"));
        noButton->setGeometry(QRect(250, 210, 75, 23));

        retranslateUi(quitwindow);

        QMetaObject::connectSlotsByName(quitwindow);
    } // setupUi

    void retranslateUi(QDialog *quitwindow)
    {
        quitwindow->setWindowTitle(QApplication::translate("quitwindow", "Dialog", 0, QApplication::UnicodeUTF8));
        label->setText(QApplication::translate("quitwindow", "are you sure to quit?", 0, QApplication::UnicodeUTF8));
        yesButton->setText(QApplication::translate("quitwindow", "yes", 0, QApplication::UnicodeUTF8));
        noButton->setText(QApplication::translate("quitwindow", "no", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class quitwindow: public Ui_quitwindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QUITWINDOW_H
