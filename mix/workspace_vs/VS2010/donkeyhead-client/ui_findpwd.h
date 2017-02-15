/********************************************************************************
** Form generated from reading UI file 'findpwd.ui'
**
** Created: Fri Jul 16 13:24:39 2010
**      by: Qt User Interface Compiler version 4.6.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_FINDPWD_H
#define UI_FINDPWD_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QDialog>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QPushButton>

QT_BEGIN_NAMESPACE

class Ui_findpwd
{
public:
    QLabel *label;
    QLabel *label_2;
    QLineEdit *lineEdit;
    QPushButton *pushButton;

    void setupUi(QDialog *findpwd)
    {
        if (findpwd->objectName().isEmpty())
            findpwd->setObjectName(QString::fromUtf8("findpwd"));
        findpwd->resize(339, 190);
        label = new QLabel(findpwd);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(140, 20, 111, 16));
        label_2 = new QLabel(findpwd);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setGeometry(QRect(40, 72, 111, 20));
        lineEdit = new QLineEdit(findpwd);
        lineEdit->setObjectName(QString::fromUtf8("lineEdit"));
        lineEdit->setGeometry(QRect(130, 70, 113, 20));
        pushButton = new QPushButton(findpwd);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));
        pushButton->setGeometry(QRect(130, 140, 75, 23));

        retranslateUi(findpwd);

        QMetaObject::connectSlotsByName(findpwd);
    } // setupUi

    void retranslateUi(QDialog *findpwd)
    {
        findpwd->setWindowTitle(QApplication::translate("findpwd", "Dialog", 0, QApplication::UnicodeUTF8));
        label->setText(QApplication::translate("findpwd", "\346\211\276\345\233\236\345\257\206\347\240\201", 0, QApplication::UnicodeUTF8));
        label_2->setText(QApplication::translate("findpwd", "\350\276\223\345\205\245\346\202\250\347\232\204qq\345\217\267", 0, QApplication::UnicodeUTF8));
        pushButton->setText(QApplication::translate("findpwd", "\346\217\220\344\272\244", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class findpwd: public Ui_findpwd {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_FINDPWD_H
