/********************************************************************************
** Form generated from reading UI file 'crt_cpuview.ui'
**
** Created: Mon Jul 8 10:58:25 2013
**      by: Qt User Interface Compiler version 4.8.4
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CRT_CPUVIEW_H
#define UI_CRT_CPUVIEW_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CRT_CPUViewClass
{
public:

    void setupUi(QWidget *CRT_CPUViewClass)
    {
        if (CRT_CPUViewClass->objectName().isEmpty())
            CRT_CPUViewClass->setObjectName(QString::fromUtf8("CRT_CPUViewClass"));
        CRT_CPUViewClass->resize(681, 316);

        retranslateUi(CRT_CPUViewClass);

        QMetaObject::connectSlotsByName(CRT_CPUViewClass);
    } // setupUi

    void retranslateUi(QWidget *CRT_CPUViewClass)
    {
        CRT_CPUViewClass->setWindowTitle(QApplication::translate("CRT_CPUViewClass", "CPU\346\250\241\346\213\237", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CRT_CPUViewClass: public Ui_CRT_CPUViewClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CRT_CPUVIEW_H
