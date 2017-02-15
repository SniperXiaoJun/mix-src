#-------------------------------------------------
#
# Project created by QtCreator 2012-09-11T10:06:54
#
#-------------------------------------------------

QT       += core gui xml

TARGET = XmlTest
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    CConfigXML.cpp \
    xml_operation.cpp

HEADERS  += mainwindow.h \
    CConfigXML.h \
    xml_operation.h

FORMS    += mainwindow.ui

OTHER_FILES += \
    qtdemo.rc
