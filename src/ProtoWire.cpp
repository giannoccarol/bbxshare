#include "ProtoWire.hpp"

namespace ProtoWire {

Reader::Reader(const QByteArray &data)
    : m_data(data), m_pos(0), m_valid(true)
{
}

bool Reader::readVarint(quint64 *value)
{
    quint64 result = 0;
    for (int shift = 0; shift < 64 && m_pos < m_data.size(); shift += 7) {
        const unsigned char byte = (unsigned char)m_data.at(m_pos++);
        result |= ((quint64)(byte & 0x7f)) << shift;
        if (!(byte & 0x80)) {
            *value = result;
            return true;
        }
    }
    m_valid = false;
    return false;
}

bool Reader::next(Field *field)
{
    if (!m_valid || m_pos >= m_data.size())
        return false;

    quint64 key = 0;
    if (!readVarint(&key) || key == 0) {
        m_valid = false;
        return false;
    }

    field->number = (int)(key >> 3);
    field->wireType = (int)(key & 7);
    field->value = 0;
    field->bytes.clear();

    if (field->wireType == 0)
        return readVarint(&field->value);

    if (field->wireType == 1) {
        if (m_pos + 8 > m_data.size()) {
            m_valid = false;
            return false;
        }
        m_pos += 8;
        return true;
    }

    if (field->wireType == 2) {
        quint64 size = 0;
        if (!readVarint(&size) || size > (quint64)(m_data.size() - m_pos)) {
            m_valid = false;
            return false;
        }
        field->bytes = m_data.mid(m_pos, (int)size);
        m_pos += (int)size;
        return true;
    }

    if (field->wireType == 5) {
        if (m_pos + 4 > m_data.size()) {
            m_valid = false;
            return false;
        }
        m_pos += 4;
        return true;
    }

    m_valid = false;
    return false;
}

bool varint(const QByteArray &data, int number, quint64 *value)
{
    Reader reader(data);
    Field field;
    while (reader.next(&field)) {
        if (field.number == number && field.wireType == 0) {
            *value = field.value;
            return true;
        }
    }
    return false;
}

bool bytes(const QByteArray &data, int number, QByteArray *value)
{
    Reader reader(data);
    Field field;
    while (reader.next(&field)) {
        if (field.number == number && field.wireType == 2) {
            *value = field.bytes;
            return true;
        }
    }
    return false;
}

QList<QByteArray> repeatedBytes(const QByteArray &data, int number)
{
    QList<QByteArray> values;
    Reader reader(data);
    Field field;
    while (reader.next(&field)) {
        if (field.number == number && field.wireType == 2)
            values.append(field.bytes);
    }
    return values;
}

static void rawVarint(QByteArray *out, quint64 value)
{
    do {
        unsigned char byte = (unsigned char)(value & 0x7f);
        value >>= 7;
        if (value)
            byte |= 0x80;
        out->append((char)byte);
    } while (value);
}

void appendVarint(QByteArray *out, int number, quint64 value)
{
    rawVarint(out, ((quint64)number << 3));
    rawVarint(out, value);
}

void appendBytes(QByteArray *out, int number, const QByteArray &value)
{
    rawVarint(out, ((quint64)number << 3) | 2);
    rawVarint(out, (quint64)value.size());
    out->append(value);
}

void appendString(QByteArray *out, int number, const QString &value)
{
    appendBytes(out, number, value.toUtf8());
}

} // namespace ProtoWire
