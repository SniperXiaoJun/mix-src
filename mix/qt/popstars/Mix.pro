#-------------------------------------------------
#
# Project created by QtCreator 2015-11-05T15:49:01
#
#-------------------------------------------------

QT       += core gui sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Mix
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    failedform.cpp \
    form.cpp \
    mainboard.cpp \
    ranklistform.cpp \
    star.cpp \
    mixbuttonstar.cpp

HEADERS  += mainwindow.h \
    failedform.h \
    form.h \
    mainboard.h \
    ranklistform.h \
    star.h \
    mixbuttonstar.h

FORMS    += mainwindow.ui \
    failedform.ui \
    form.ui \
    ranklistform.ui \
    mainboard.ui

CONFIG += mobility
MOBILITY = 

RESOURCES += \
    src.qrc

