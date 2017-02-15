TEMPLATE = app
TARGET = CInbox
QT += core \
    gui
HEADERS += CInboxCWidget.h \
    CInboxMenuBar.h \
    CInbox.h
SOURCES += CInboxCWidget.cpp \
    CInboxMenuBar.cpp \
    CInbox_reg.rss \
    main.cpp \
    CInbox.cpp
FORMS += CInboxCWidget.ui \
    CInbox.ui
RESOURCES += Rsource.qrc
symbian:TARGET.UID3 = 0xE492CF00
