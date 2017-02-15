# -------------------------------------------------
# Project created by QtCreator 2010-07-15T14:14:34
# -------------------------------------------------
QT += network \
    opengl \
    sql \
    xml
TARGET = clientappv3
TEMPLATE = app
SOURCES += main.cpp \
    login.cpp \
    regdialog.cpp \
    panel.cpp \
    chatform.cpp
HEADERS += login.h \
    regdialog.h \
    panel.h \
    chatform.h
FORMS += login.ui \
    regdialog.ui \
    panel.ui \
    chatform.ui
RESOURCES += client.qrc
RC_FILE  = icon.rc
