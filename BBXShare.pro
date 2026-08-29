APP_NAME = BBXShare

CONFIG += qt warn_on cascades10

SOURCES += src/main.cpp \
    src/ShareService.cpp \
    src/ProtoWire.cpp \
    src/QuickShareSession.cpp \
    src/QuickShareSender.cpp

HEADERS += src/ShareService.hpp \
    src/ProtoWire.hpp \
    src/QuickShareSession.hpp \
    src/QuickShareSender.hpp

LIBS += -lcrypto -lbbsystem -lbbcascadespickers
