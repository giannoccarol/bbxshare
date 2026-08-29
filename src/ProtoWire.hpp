#ifndef PROTOWIRE_HPP_
#define PROTOWIRE_HPP_

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtCore/QtGlobal>

namespace ProtoWire {

struct Field {
    int number;
    int wireType;
    quint64 value;
    QByteArray bytes;
};

class Reader {
public:
    explicit Reader(const QByteArray &data);
    bool next(Field *field);
    bool valid() const { return m_valid; }

private:
    bool readVarint(quint64 *value);

    QByteArray m_data;
    int m_pos;
    bool m_valid;
};

bool varint(const QByteArray &data, int number, quint64 *value);
bool bytes(const QByteArray &data, int number, QByteArray *value);
QList<QByteArray> repeatedBytes(const QByteArray &data, int number);

void appendVarint(QByteArray *out, int number, quint64 value);
void appendBytes(QByteArray *out, int number, const QByteArray &value);
void appendString(QByteArray *out, int number, const QString &value);

} // namespace ProtoWire

#endif
