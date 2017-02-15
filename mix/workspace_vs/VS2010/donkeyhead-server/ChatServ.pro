# -------------------------------------------------
# Project created by QtCreator 2010-05-08T09:32:46
# -------------------------------------------------
QT += network \
    opengl \
    sql \
    xml
TARGET = ChatServ
TEMPLATE = app
SOURCES += main.cpp \
    daemon.cpp \
    tcpsockserver.cpp \
    tcpconthread.cpp \
    sqlitedb.cpp \
    mysqlquerymodel.cpp
HEADERS += daemon.h \
    tcpsockserver.h \
    tcpconthread.h \
    sqlitedb.h \
    mysqlquerymodel.h
FORMS += daemon.ui
RC_FILE = icon.rc

RESOURCES += \
    resources.qrc
