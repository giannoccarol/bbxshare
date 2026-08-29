APP_NAME = BBXShare

CONFIG += qt warn_on cascades10

SOURCES += src/main.cpp \
    src/DiscoveryUtils.cpp \
    src/ShareService.cpp \
    src/ProtoWire.cpp \
    src/QuickShareSession.cpp \
    src/QuickShareSender.cpp

HEADERS += src/ShareService.hpp \
    src/DiscoveryUtils.hpp \
    src/ProtoWire.hpp \
    src/QuickShareSession.hpp \
    src/QuickShareSender.hpp

LIBS += -lcrypto -lbbsystem -lbbcascadespickers -lbtapi

TRANSLATIONS += \
    assets/translations/bbxshare_en.ts \
    assets/translations/bbxshare_de.ts \
    assets/translations/bbxshare_fr.ts \
    assets/translations/bbxshare_es.ts \
    assets/translations/bbxshare_nl.ts

RESOURCES += assets/translations.qrc

CONFIG += lrelease
