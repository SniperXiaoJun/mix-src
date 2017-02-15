/********************************************************************************
** Form generated from reading UI file 'screenshot.ui'
**
** Created: Sat Jul 6 09:15:23 2013
**      by: Qt User Interface Compiler version 4.8.4
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SCREENSHOT_H
#define UI_SCREENSHOT_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ScreenShotClass
{
public:

    void setupUi(QWidget *ScreenShotClass)
    {
        if (ScreenShotClass->objectName().isEmpty())
            ScreenShotClass->setObjectName(QString::fromUtf8("ScreenShotClass"));
        ScreenShotClass->resize(400, 300);

        retranslateUi(ScreenShotClass);

        QMetaObject::connectSlotsByName(ScreenShotClass);
    } // setupUi

    void retranslateUi(QWidget *ScreenShotClass)
    {
        ScreenShotClass->setWindowTitle(QApplication::translate("ScreenShotClass", "Form", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class ScreenShotClass: public Ui_ScreenShotClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SCREENSHOT_H
