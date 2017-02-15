TEMPLATE = app
TARGET = QString_QT_TEST 

QT        += core \
    gui 

HEADERS   += QString_QT_TEST.h
SOURCES   += QString_QT_TEST_reg.rss \
    main.cpp \
    QString_QT_TEST.cpp
FORMS	  += QString_QT_TEST.ui
RESOURCES +=

symbian:TARGET.UID3 = 0xE57D29D3
