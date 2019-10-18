CONFIG += c++11

TARGET = learnevent
CONFIG += console
CONFIG -= app_bundle



# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

DISTFILES +=

HEADERS += \
    addrman.h \
    basic_type.h \
    compat.h \
    net.h \
    net_args.h \
    net_params.h \
    net_processing.h \
    netaddress.h \
    netbase.h \
    netconnman.h \
    netevent.h \
    netmessage.h \
    netmessagemaker.h \
    network_macro.h \
    node.h \
    protocol.h \
    timedata.h \
    tinyformat.h \
    torcontrol.h \
    udpapi.h \
    udpnet.h \
    udprelay.h \
    utiltime.h

SOURCES += \
    addrman.cpp \
    net.cpp \
    net_processing.cpp \
    netaddress.cpp \
    netbase.cpp \
    netconnman.cpp \
    netevent.cpp \
    netmessage.cpp \
    node.cpp \
    timedata.cpp \
    torcontrol.cpp \
    udp-echo.cpp \
    udpnet.cpp \
    udprelay.cpp \
    utiltime.cpp
