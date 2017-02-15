QT       += core gui network sql

TARGET = YY_CHAT
TEMPLATE = app


HEADERS += \
    YY_CHAT_ThreadServer.h \
    YY_CHAT_ThreadClient.h \
    yy_chat.h \
    CSetDialog.h \
    comm.h \
    CGeneralMsgClass.h \
    CChatDialog.h \
    IBaseDataMessage.h \
    IBaseDataField.h \
    CBaseDataMessage.h \
    CBaseDataField.h \
    CBaseData.h

SOURCES += \
    YY_CHAT_ThreadServer.cpp \
    YY_CHAT_ThreadClient.cpp \
    yy_chat.cpp \
    main.cpp \
    CSetDialog.cpp \
    CGeneralMsgClass.cpp \
    CChatDialog.cpp \
    CBaseDataMessage.cpp \
    CBaseDataField.cpp \
    CBaseData.cpp

FORMS += \
    CSetDialog.ui \
    CChatDialog.ui \
    yy_chat.ui

RESOURCES += \
    yy_chat.qrc

