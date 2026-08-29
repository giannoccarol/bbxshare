#include "../src/ProtoWire.hpp"

#include <QtCore/QCoreApplication>
#include <stdio.h>

static int check(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    QByteArray child;
    ProtoWire::appendVarint(&child, 1, 100);
    ProtoWire::appendBytes(&child, 2, QByteArray("commitment"));

    QByteArray message;
    ProtoWire::appendVarint(&message, 1, 1);
    ProtoWire::appendBytes(&message, 3, child);
    ProtoWire::appendBytes(&message, 3, child);
    ProtoWire::appendVarint(&message, 8, (quint64)(qint64)-42);

    quint64 version = 0, signedValue = 0, cipher = 0;
    QByteArray decodedChild, commitment;
    if (check(ProtoWire::varint(message, 1, &version) && version == 1,
              "varint round-trip")) return 1;
    if (check(ProtoWire::bytes(message, 3, &decodedChild), "nested bytes")) return 1;
    if (check(ProtoWire::varint(decodedChild, 1, &cipher) && cipher == 100,
              "nested varint")) return 1;
    if (check(ProtoWire::bytes(decodedChild, 2, &commitment) &&
              commitment == "commitment", "nested payload")) return 1;
    if (check(ProtoWire::repeatedBytes(message, 3).size() == 2,
              "repeated bytes")) return 1;
    if (check(ProtoWire::varint(message, 8, &signedValue) &&
              (qint64)signedValue == -42, "negative int64 encoding")) return 1;

    QByteArray malformed;
    malformed.append((char)0x12);
    malformed.append((char)0x7f);
    ProtoWire::Reader reader(malformed);
    ProtoWire::Field field;
    if (check(!reader.next(&field) && !reader.valid(), "bounds check")) return 1;

    puts("OK - protobuf wire encoder/decoder");
    return 0;
}
