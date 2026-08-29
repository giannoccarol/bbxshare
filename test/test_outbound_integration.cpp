#include "ShareServiceStub.hpp"
#include "../src/QuickShareSender.hpp"
#include "../src/QuickShareSession.hpp"

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir temporary;
    if (!temporary.isValid()) return 1;

    const QString sourcePath = temporary.path() + "/payload.bin";
    const QString secondSourcePath = temporary.path() + "/second.txt";
    const QString receiveDir = temporary.path() + "/received";
    QByteArray expected;
    expected.resize(700 * 1024 + 37);
    for (int i = 0; i < expected.size(); ++i)
        expected[i] = (char)((i * 31 + 7) & 0xff);
    QFile source(sourcePath);
    if (!source.open(QIODevice::WriteOnly) || source.write(expected) != expected.size())
        return 2;
    source.close();
    const QByteArray secondExpected("secondo payload BBX Share\n");
    QFile secondSource(secondSourcePath);
    if (!secondSource.open(QIODevice::WriteOnly) ||
        secondSource.write(secondExpected) != secondExpected.size())
        return 2;
    secondSource.close();
    qputenv("BBXSHARE_DOWNLOAD_DIR", receiveDir.toLocal8Bit());

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return 3;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    socklen_t addressLength = sizeof(address);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &addressLength) != 0)
        return 4;

    ShareService service;
    bool receiverResult = false;
    std::thread receiver([&]() {
        int connection = accept(listener, 0, 0);
        if (connection < 0) return;
        QuickShareSession session(connection, QString::fromLatin1("127.0.0.1"),
                                  &service);
        receiverResult = session.run();
    });

    QuickShareSender sender(QStringList() << sourcePath << secondSourcePath,
                            QString::fromLatin1("127.0.0.1"),
                            ntohs(address.sin_port),
                            QString::fromLatin1("Receiver test"),
                            QString::fromLatin1("Sender test"), &service);
    const bool senderResult = sender.run();
    receiver.join();
    close(listener);
    app.processEvents();

    QFile received(receiveDir + "/payload.bin");
    if (!received.open(QIODevice::ReadOnly)) {
        fprintf(stderr, "FAIL file principale assente; senderResult=%d receiverResult=%d sender=%s receiver=%s\n",
                senderResult, receiverResult,
                service.lastSendStatus().toUtf8().constData(),
                service.lastStatus().toUtf8().constData());
        return 5;
    }
    const QByteArray actual = received.readAll();
    QFile secondReceived(receiveDir + "/second.txt");
    if (!secondReceived.open(QIODevice::ReadOnly)) {
        fprintf(stderr, "FAIL secondo file assente; senderResult=%d receiverResult=%d sender=%s receiver=%s\n",
                senderResult, receiverResult,
                service.lastSendStatus().toUtf8().constData(),
                service.lastStatus().toUtf8().constData());
        return 5;
    }
    const QByteArray secondActual = secondReceived.readAll();
    if (!senderResult || !receiverResult || actual != expected ||
        secondActual != secondExpected) {
        fprintf(stderr, "FAIL sender=%d receiver=%d bytes=%d/%d\n",
                senderResult, receiverResult, actual.size(), expected.size());
        return 6;
    }
    printf("OK - invio multi-file cifrato, %d byte verificati\n",
           actual.size() + secondActual.size());
    return 0;
}
